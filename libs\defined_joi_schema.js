const _ = require('lodash');
const Joi = require('@hapi/joi');

module.exports = function (app) {
  const wrapper = {};
  wrapper.get_schema = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const schema = {};
        const __details = _.get(options, ['external_fields'], {});
        for (const __property in __details) {
          const __mapper = _.get(__details, __property, {});
          if (__mapper.primary || __mapper.session) {
            continue;
          }
          const __data_type_fn = app.libs.schema[__mapper.data_type];
          schema[__property] =
            __data_type_fn && typeof __data_type_fn === 'function' ? __data_type_fn(__mapper.options || {}) : Joi.any();
          if (_.get(__mapper, 'required')) {
            schema[__property] = schema[__property].required();
          } else {
            schema[__property] = schema[__property].allow(null);
          }
        }
        return resolve(Joi.object(schema));
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({ e, reject, get_schema: 'extra_fields' });
      }
    });
  };

  wrapper.get_schema_for_update = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const schema = {};
        const __details = _.get(options, ['external_fields'], {});
        for (const __property in __details) {
          const __mapper = _.get(__details, __property, {});
          if (!__mapper.alterable || __mapper.primary || __mapper.session) {
            continue;
          }
          const __data_type_fn = app.libs.schema[__mapper.data_type];
          schema[__property] =
            __data_type_fn && typeof __data_type_fn === 'function' ? __data_type_fn(__mapper.options || {}) : Joi.any();
          schema[__property] = schema[__property].allow(null);
        }
        return resolve(Joi.object(schema));
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({ e, reject, get_schema: 'get_schema_for_update' });
      }
    });
  };

  return wrapper;
};
