const _ = require('lodash');
const Joi = require('@hapi/joi');

module.exports = function (app) {
  const wrapper = {};

  wrapper.joi_validation_v1 = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const { schema } = options;

        const result = Joi.validate(options.data, schema);
        if (_.get(result.error, 'name') === 'ValidationError') {
          return reject(new app.libs.customError(_.get(result.error, ['details', '0', 'message']), 400));
        }

        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({ e, reject, function_name: 'joi_validation_v1' });
      }
    });
  };

  wrapper.validate_argument_v1 = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!_.get(options, 'params_argument') && !_.get(options, 'table_name')) {
          return reject(new app.libs.customError('validate_argument not found', 400));
        }

        const params_argument = _.get(options, 'params_argument');
        const table_name = _.get(options, 'table_name');

        const __o = {};
        __o[params_argument] = Joi.string().required();
        const params_schema = Joi.object().keys(__o);

        const params_result = Joi.validate(options.params, params_schema);

        if (_.get(params_result.error, 'name') === 'ValidationError') {
          return reject(new app.libs.customError(_.get(params_result.error, ['details', '0', 'message']), 400));
        }

        const params_uuid = _.get(options.params, params_argument);
        // fetch all the values here
        const __q = { table_name, uuid: params_uuid };

        let __param_prev = await app.db.records(__q);

        if (_.size(__param_prev) === 0) {
          return reject(new app.libs.customError(`${params_argument} does not exists`, 400));
        }
        __param_prev = app.libs.utils.checkFirstRecord(__param_prev);
        return resolve(__param_prev);
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'validate_argument_v1',
          options,
        });
      }
    });
  };

  return wrapper;
};
