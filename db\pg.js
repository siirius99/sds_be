const Joi = require('@hapi/joi');
const _ = require('lodash');

module.exports = function (app) {
  const schema = {};

  schema.smallint = function () {
    return Joi.number().integer().min(-32768).max(32767);
  };

  schema.integer = function () {
    return Joi.number().integer();
  };

  schema.decimal = function () {
    return Joi.number();
  };

  schema.numeric = function () {
    return Joi.number();
  };

  schema.varchar = function (options) {
    const __s = Joi.string();
    return _.get(options, 'max_length') ? __s.max(_.get(options, 'max_length')) : __s;
  };

  schema.uuid = function () {
    return Joi.string().guid();
  };

  schema.boolean = function () {
    return Joi.boolean();
  };

  schema.date = function () {
    return Joi.date();
  };

  schema.text = function () {
    return Joi.string();
  };

  return schema;
};
