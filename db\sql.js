const Joi = require('@hapi/joi');
const _ = require('lodash');

module.exports = function (app) {
  const schema = {};

  schema.datetime = function () {
    return Joi.date();
  };

  schema.integer = function () {
    return Joi.number().integer();
  };

  schema.decimal = function () {
    return Joi.number();
  };

  schema.string = function (options) {
    const __s = Joi.string();
    return _.get(options, 'max_length') ? __s.max(_.get(options, 'max_length')) : __s;
  };

  schema.boolean = function () {
    return Joi.number().max(1).min(0);
  };

  schema.uuid = function () {
    return Joi.string().guid();
  };

  return schema;
};
