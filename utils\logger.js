const winston = require('winston');
const _ = require('lodash');
const moment = require('moment');

let __app;
const enumerateErrorFormat = winston.format((info) => {
  if (info instanceof Error) {
    Object.assign(info, { message: info.stack });
  }
  return info;
});

const logger = winston.createLogger({
  level: 'debug',
  format: winston.format.combine(
    winston.format((info) => {
      info.timestamp = moment().format('YYYY-MM-DD HH:mm:ss');
      return info;
    })(),
    enumerateErrorFormat(),
    winston.format.colorize(),
    winston.format.splat(),
    winston.format.printf(({ level, message, timestamp }) => `[${timestamp}] ${level}: ${message}`)
  ),
  transports: [
    new winston.transports.Console({
      stderrLevels: ['error'],
    }),
  ],
});

const x = {
  set_app_object(_app) {
    __app = _app;
  },

  // Logging methods
  info(message) {
    logger.info(message);
  },

  error(message) {
    logger.error(message);
  },

  warn(message) {
    logger.warn(message);
  },

  debug(message) {
    logger.debug(message);
  },
};

module.exports = x;
