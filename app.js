const express = require('express');
const createError = require('http-errors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const moment = require('moment');
const uuid = require('uuid');

const app = express();

app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

app.log = require('./utils/logger');

app.log.set_app_object(app);

app.use(bodyParser.urlencoded({ extended: false, limit: '50mb' }));
app.use((req, res, next) => {
  if (req.originalUrl === '/stripe_webhook') {
    next();
  } else {
    bodyParser.json({ limit: '50mb' })(req, res, next);
  }
});
app.use((req, res, next) => {
  if (req.originalUrl === '/stripe_webhook') {
    next();
  } else {
    express.json({ limit: '50mb' })(req, res, next);
  }
});
app.use(cookieParser());

app.use((req, res, next) => {
  req.trace_id = `${req.path}_${moment.utc().format('YYYYMMDDHHmmss')}`;
  req.tracer_request_uuid = uuid.v4();
  app.log.info(`New request - trace_id: ${req.trace_id}, tracer_request_uuid: ${req.tracer_request_uuid}`);
  next();
});

app.use(cors());

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
});

app.use(limiter);

require('./utils/loader')(app);

app.use((req, res, next) => {
  next(createError(404));
});

app.logp = function (key, value) {
  app.log.info(`${key}: ${JSON.stringify(value)}`);
};

app.use((err, req, res, next) => {
  app.log.error(`Error - trace_id: ${req.trace_id}, tracer_request_uuid: ${req.tracer_request_uuid}, ${err.stack}`);
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
