const _ = require('lodash');
const Joi = require('@hapi/joi');
const bcrypt = require('bcrypt');

module.exports = function (app) {
  const wrapper = {};

  wrapper.get_crud = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const eligible_tables = app.libs.utils.pluck(
          _.filter(_.get(app.mysql_schema, ['tables']), { crud_get_enabled: true }),
          'name'
        );
        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            table_name: Joi.string().valid(eligible_tables).required(),
          }),
          data: options.params,
        });

        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            taql: Joi.string(),
          }),
          data: options.query,
        });

        let __taql = _.get(options, 'query.taql');
        if (typeof __taql === 'string') {
          __taql = JSON.parse(__taql);
        }

        const __res = await app.db.taql_parser_and_search({
          table_name: options.params.table_name,
          query: { taql: __taql },
          user_info: options.user_info,
        });

        // const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), { name: options.params.table_name });
        // const __hide_fields = new Set();
        // for (const __column in _.get(__crud_details, 'external_fields') || {}) {
        //   if (_.get(__crud_details, ['external_fields', __column, 'display']) === false) {
        //     __hide_fields.add(__column);
        //   }
        // }
        // if (_.size(_.get(__res, 'data'))) {
        //   __res.data = _.map(_.get(__res, 'data'), function (__d) {
        //     return _.omit(__d, ...(Array.from(__hide_fields) || []));
        //   });
        // }
        return resolve(__res);
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'get_crud',
          options,
        });
      }
    });
  };

  wrapper.post_crud = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const eligible_tables = app.libs.utils.pluck(
          _.filter(_.get(app.mysql_schema, ['tables']), { crud_post_enabled: true }),
          'name'
        );
        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            table_name: Joi.string().valid(eligible_tables).required(),
          }),
          data: options.params,
        });

        const __table_name = options.params.table_name;

        const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), { name: __table_name });

        const __details = _.get(__crud_details, 'external_fields', {});

        await app.libs.validation.joi_validation_v1({
          schema: await app.libs.defined_joi_schema.get_schema({
            table_name: __table_name,
            operation: 'insert',
            data: options.body,
            external_fields: __details,
          }),
          data: options.body,
        });

        let __body = options.body;
        if (_.get(__crud_details, 'tenant')) {
          __body = await app.libs.crud.encrypt_user_password({ body: __body, user_info: options.user_info });
        }
        const __value = _.merge(
          __body,
          app.libs.utils.get_basic_insert_details({ user_info: options.user_info, table_name: __table_name })
        );
        const __inset = await app.db.insert_record({
          table_name: __table_name,
          record: __value,
        });

        return resolve({ message: 'Registered successfully', uuid: _.get(__value, 'uuid') });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'post_crud',
          options,
        });
      }
    });
  };

  wrapper.put_crud = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const eligible_tables = app.libs.utils.pluck(
          _.filter(_.get(app.mysql_schema, ['tables']), { crud_put_enabled: true }),
          'name'
        );
        let __body = options.body;
        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            table_name: Joi.string().valid(eligible_tables).required(),
            id: Joi.string().required(),
          }),
          data: options.params,
        });

        if (_.size(__body) === 0) {
          return reject(new app.libs.customError('Request body is required', 400));
        }

        const __table_name = options.params.table_name;
        const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), { name: __table_name });
        const __field_details = _.get(__crud_details, 'external_fields') || {};
        const __primary_key = _.findKey(__field_details, { primary: true });
        if (!__primary_key) {
          return reject(new app.libs.customError('Primary key not configured', 404));
        }
        const crud_update_columns = [];
        for (const item in __field_details) {
          if (_.get(__field_details, [item, 'alterable'])) {
            crud_update_columns.push(item);
          }
        }

        await app.libs.validation.joi_validation_v1({
          schema: await app.libs.defined_joi_schema.get_schema_for_update({
            table_name: __table_name,
            external_fields: __field_details,
          }),
          data: __body,
        });

        for (const __key in __body) {
          if (crud_update_columns.indexOf(__key) === -1) {
            return reject(new app.libs.customError(`${__key} is not allowed for update`, 400));
          }
        }

        const __q = { table_name: __table_name, [__primary_key]: options.params.id };

        const __record = await app.db.records(__q);

        if (_.size(__record) === 0) {
          return reject(new app.libs.customError('Record not found', 404));
        }

        if (_.get(__crud_details, 'tenant')) {
          __body = await app.libs.crud.encrypt_user_password({ body: __body, user_info: options.user_info });
        }

        await app.db.update_record_by_ID_or_UUID({
          table_name: __table_name,
          id: options.params.id,
          identifier: __primary_key,
          update: _.merge(
            __body,
            app.libs.utils.get_basic_insert_details({ meta: { update: true }, user_info: options.user_info })
          ),
        });

        return resolve({ message: 'Updated successfully' });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'put_crud',
          options,
        });
      }
    });
  };

  wrapper.encrypt_user_password = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (_.get(options, 'body.password')) {
          const salt = await bcrypt.genSalt(app.config.salt_rounds);
          const hash = await bcrypt.hash(_.get(options, 'body.password', 'NA'), salt);
          _.set(options, 'body.password', hash);
        }
        return resolve(_.get(options, 'body'));
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'encrypt_user_password',
          options,
        });
      }
    });
  };

  return wrapper;
};
