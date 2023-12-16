module.exports = async function (app) {
  const constants = require('../libs/const.json');
  app.constants = constants;
  app.log.info('Loaded constants from const.json');

  const mysqlSchema = require('../libs/mysql_schema.json');
  app.mysql_schema = mysqlSchema;
  app.log.info('Loaded MySQL schema from mysql_schema.json');

  const config = require('../config.json');
  app.config = config;
  app.log.info('Loaded configuration from config file');

  const knex = require('../libs/knex')(app);
  knex.init();
  app.db = knex;
  app.log.info('Initialized Knex for database operations');

  app.libs = {};
  app.libs.customError = require('../libs/Error').customError;
  app.libs.defined_joi_schema = require('../libs/defined_joi_schema')(app);
  app.log.info('Loaded defined Joi schemas');

  require('../routes/swagger')(app);
  app.log.info('Loaded Swagger routes');

  app.libs.validation = require('../libs/validation')(app);
  app.log.info('Loaded validation module');

  app.libs.crud = require('../libs/crud')(app);
  app.log.info('Loaded CRUD operations module');

  app.libs.payment = require('../libs/payment')(app);
  app.log.info('Loaded payment module');

  const crudController = require('../controllers/crud')(app);
  app.crud_controller = crudController;
  app.log.info('Loaded CRUD controller');

  const index_controller = require('../controllers/index')(app);
  app.index_controller = index_controller;
  app.log.info('Loaded Index controller');

  const payment_controller = require('../controllers/payment')(app);
  app.payment_controller = payment_controller;
  app.log.info('Loaded payment controller');

  app.libs.error_handler = require('../libs/error_handler')(app);
  app.log.info('Loaded error handling module');

  app.libs.utils = require('../libs/utils')(app);
  app.log.info('Loaded utility functions module');

  app.libs.middleware = require('../libs/middleware')(app);
  app.use(app.libs.middleware.authenticate);

  if (app.config.client === 'pg') {
    app.libs.schema = require('../db/pg')(app);
  } else {
    app.libs.schema = require('../db/sql')(app);
  }
  app.log.info('Determined database schema based on client type');

  app.libs.auth = require('../libs/auth')(app);

  require('../routes/crud')(app);
  app.log.info('Loaded CRUD routes');

  require('../routes/index')(app);
  app.log.info('Loaded Index routes');

  require('../routes/payment')(app);
  app.log.info('Loaded Index routes');
};
