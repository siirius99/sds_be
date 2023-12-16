const _ = require('lodash');
const uuid = require('uuid');
const Joi = require('@hapi/joi');
// coppied
module.exports = function (app) {
  const db = {};

  db.init = function () {
    const mysqlConfig = app.config.mysql;

    for (const key in mysqlConfig) {
      if (Object.hasOwnProperty.call(mysqlConfig, key)) {
        if (!mysqlConfig[key]) {
          throw new Error(`Please provide a valid mysql ${key}`);
        }
      }
    }
    app.config.pool.afterCreate = function (conn, cbConnectionVerfied) {
      conn.query('select 1', function (err, data) {
        if (err) {
          throw new Error('knex connection error', err);
        } else {
          console.log('new knex connection created');
        }
        cbConnectionVerfied(err, conn);
      });
    };

    const knex = require('knex')({
      client: app.config.client,
      connection: app.config.connection,
      pool: app.config.pool,
    });
    app.knex = knex;
  };

  /*
        Responsible for fetching records from any MYSQL table
    */
  db.records = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const { internal_settings } = options;
        delete options.internal_settings;
        const options_copy = _.cloneDeep(options);
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }
        let q = app.knex(options.table_name);
        delete options.table_name;

        if (options.sorting) {
          // q.select(options.fields)
          delete options.sorting;
        } else {
          q = q.orderBy('id', 'desc');
        }
        if (options.fields) {
          q.select(options.fields);
          delete options.fields;
        }
        _.mapKeys(options, function (value, key) {
          if (typeof value === 'object') {
            q = q.whereIn(key, value);
          } else {
            q = q.andWhere(key, '=', value);
          }
        });
        if (_.get(internal_settings, 'only_query_object') === true) {
          return resolve({ query_object: q });
        }
        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            return app.libs.error_handler.non_controller_handler({
              e: err,
              reject,
              function_name: 'records',
              options: options_copy,
            });
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'records',
          options,
        });
      }
    });
  };

  db.records_null_support = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const { internal_settings } = options;
        delete options.internal_settings;
        const options_copy = _.cloneDeep(options);
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }
        let q = app.knex(options.table_name);
        delete options.table_name;

        if (options.sorting) {
          // q.select(options.fields)
          delete options.sorting;
        } else {
          q = q.orderBy('id', 'desc');
        }
        if (options.fields) {
          q.select(options.fields);
          delete options.fields;
        }
        _.mapKeys(options, function (value, key) {
          if (value === null) {
            q = q.havingNull(key);
          } else if (typeof value === 'object') {
            q = q.whereIn(key, value);
          } else {
            q = q.andWhere(key, '=', value);
          }
        });
        if (_.get(internal_settings, 'only_query_object') === true) {
          return resolve({ query_object: q });
        }
        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            return app.libs.error_handler.non_controller_handler({
              e: err,
              reject,
              function_name: 'records_null_support',
              options: options_copy,
            });
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'records_null_support',
          options,
        });
      }
    });
  };

  /*
        Responsible for inserting records in any MYSQL table
    */
  db.insert_record = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }

        await app.knex(options.table_name).insert(options.record).returning('id', 'uuid').then(resolve, reject);
        resolve('success');
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'insert_record',
          options,
        });
      }
    });
  };

  db.insert_multiple_records = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }
        app.knex(options.table_name).insert(options.records).returning(['uuid']).then(resolve, reject);
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'insert_multiple_records',
          options,
        });
      }
    });
  };

  /*
        Responsible for updating record of any MYSQL table (based on prime attributes ID/UUID)
    */
  db.update_record_by_ID_or_UUID = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }

        const q = app.knex(options.table_name);

        q.where(options.identifier, options.id);
        q.update(options.update);

        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            console.log('error in update_record_by_ID_or_UUID ', err, 'options', options);
            return reject(new app.libs.customError(app.constants.error_message, 500));
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'update_record_by_ID_or_UUID',
          options,
        });
      }
    });
  };

  db.raw = function (options) {
    const self = this;
    return new Promise(async function (resolve, reject) {
      try {
        let __res = [];
        if (options.sql) {
          __res = await app.knex.raw(options.sql);
          [__res] = __res;
          __res = app.libs.utils.parseIntoJson(app.libs.utils.parseIntoString(__res));
        }
        return resolve({ data: __res });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'raw',
          options,
        });
      }
    });
  };

  db.raw_v1 = function (options) {
    const self = this;
    return new Promise(async function (resolve, reject) {
      try {
        let __res = [];
        if (options.sql) {
          __res = await app.knex.raw(options.sql, options.values);
          [__res] = __res;
          __res = app.libs.utils.parseIntoJson(app.libs.utils.parseIntoString(__res));
        }
        return resolve({ data: __res });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'raw_v1',
          options,
        });
      }
    });
  };

  db.taql_parser_and_search = function (options) {
    const self = this;
    return new Promise(async function (resolve, reject) {
      try {
        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            query: Joi.object().required(),
            table_name: Joi.string().required(),
            user_info: Joi.object().required(),
            super_admin: Joi.boolean(),
          }),
          data: options,
        });

        let { taql } = options.query;
        taql = app.libs.utils.parseIntoJson(taql);

        const allowed_ops = ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'like', 'range', 'isnull'];
        const allowed_ops_map = {
          eq: '=',
          gt: '>',
          gte: '>=',
          lt: '<',
          lte: '<=',
          like: 'like',
          ne: '!=',
          range: 'range',
        };
        const filter_keys = Joi.object()
          .keys({
            // "type": Joi.string().valid(["extra fields", "entity fields"]),
            name: Joi.string().required(),
            value: [Joi.string(), Joi.number(), Joi.bool()],
            op: Joi.string().valid(allowed_ops),
            values: Joi.array().items([Joi.string(), Joi.number(), Joi.bool()]),
            get_local_value: Joi.boolean(),
          })
          .xor('value', 'values');

        const sort_keys = Joi.object()
          .keys({
            order: Joi.string().valid(['desc', 'asc']).required(),
            name: Joi.string(),
            random: Joi.boolean(),
            // "type": Joi.string().valid(["extra fields", "entity fields"])
          })
          .xor('name', 'random');

        const fields_keys = Joi.object().keys({
          name: Joi.string().required(),
          readable_key: Joi.string(),
          agg: Joi.string().valid(['count', 'avg', 'sum', 'min', 'max']),
          // "type": Joi.string().valid(["extra fields", "entity fields"]),
        });

        const aggregations_keys = Joi.object().keys({
          name: Joi.string().required(),
          // "type": Joi.string().valid(["extra fields", "entity fields"]),
        });

        const aggregations_v1 = Joi.object().keys({
          aggregations: Joi.array().items(aggregations_keys).min(1).required(),
          fields: Joi.array().items(fields_keys),
        });

        const pagination_keys = Joi.object().keys({
          page_size: Joi.number().required(),
          page_num: Joi.number().required(),
        });

        const other_options_keys = Joi.object().keys({
          export_to_excel: Joi.bool(),
          count_only: Joi.bool(),
        });

        const join_keys = Joi.object().keys({
          table_name: Joi.string().required(),
          join_type: Joi.string().valid(['inner_join', 'left_join']).required(),
          left_table_attribute: Joi.string().required(),
          right_table_attribute: Joi.string().required(),
          fields: Joi.array().items(fields_keys).min(1).required(),
        });

        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            filters: Joi.array().items(filter_keys),
            sort: Joi.array().items(sort_keys),
            fields: Joi.array().items(fields_keys),
            aggregations: Joi.array().items(aggregations_keys),
            aggregations_v1,
            pagination: pagination_keys,
            other_options: other_options_keys,
            name: Joi.string(),
            joins: Joi.array().items(join_keys),
          }),
          data: taql,
        });

        const __field_map = {};

        function get_alias(options) {
          return `${options.table_name}__${options.name}`;
        }

        function get_field_name_v1(options) {
          let ret_str = '';
          if (options.type === 'join') {
            ret_str = `${options.table_name}.${options.name}`;
            if (options.alias === true) {
              const __alias = get_alias(options);
              __field_map[__alias] = ret_str;
              ret_str = `${ret_str} as ${__alias}`;
            }

            if (options.name.indexOf('.') !== -1) {
              ret_str = options.name;
            }
          } else {
            ret_str = options.name;
          }
          return ret_str;
        }

        function get_field_name(__q) {
          if (!_.isEmpty(_.get(__field_map, __q.name))) {
            return _.get(__field_map, __q.name);
          }
          // return __q.name
          return `${options.table_name}.${__q.name}`;
        }

        let query = app.knex(options.table_name);

        // code here
        // get columns and if workspace_uuid is part of it, apply it

        const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), { name: options.table_name });
        const __table_details = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
        if (__table_details) {
          if (__table_details.name === options.table_name) {
            const __primary_key = _.findKey(_.get(__table_details, 'external_fields') || {}, { primary: true });
            if (__primary_key && _.get(options, ['user_info', 'user', 'id']) !== '-1') {
              query = query.andWhere(
                get_field_name({ name: [__primary_key] }),
                '=',
                _.get(options, ['user_info', 'user', 'id'])
              );
            }
          } else {
            const __filtered_fields = _.pickBy(
              _.get(__crud_details, 'external_fields') || {},
              (field) => _.get(field, 'reference.table') === __table_details.name
            );
            if (_.size(__filtered_fields) && _.get(options, ['user_info', 'user', 'id']) !== '-1') {
              const __keys_array = Object.keys(__filtered_fields);
              query = query.andWhere(
                get_field_name({ name: [__keys_array[0]] }),
                '=',
                _.get(options, ['user_info', 'user', 'id'])
              );
            }
          }
        }

        const fields = [];
        const fields_v1 = [];

        // return all fields for base table
        if (_.size(_.get(taql, 'fields', [])) === 0 && _.size(_.get(taql, 'joins', [])) > 0) {
          fields.push(`${options.table_name}.*`);

          const __table_columns = await app.libs.utils.get_default_column_set_for_export({
            table_name: options.table_name,
          });
          if (_.size(_.get(__table_columns, 'columns', [])) > 0) {
            for (const __c of _.get(__table_columns, 'columns', [])) {
              fields_v1.push({
                name: get_field_name({ name: __c }),
              });
            }
          }
        }

        if (_.size(_.get(taql, 'fields', [])) === 0 && _.size(_.get(taql, 'joins', [])) === 0) {
          const __table_columns = await app.libs.utils.get_default_column_set_for_export({
            table_name: options.table_name,
          });
          if (_.size(_.get(__table_columns, 'columns', [])) > 0) {
            for (const __c of _.get(__table_columns, 'columns', [])) {
              fields_v1.push({
                name: get_field_name({ name: __c }),
              });
            }
          }
        }

        _.map(taql.fields, function (__q) {
          fields.push(get_field_name(__q));
          fields_v1.push({
            name: get_field_name(__q),
            readable_key: __q.readable_key,
          });
        });

        // join comes the first
        _.map(taql.joins, function (__q) {
          if (__q.join_type === 'inner_join') {
            const left_table_attribute = get_field_name_v1({
              name: __q.left_table_attribute,
              type: 'join',
              table_name: options.table_name,
            });

            const right_table_attribute = get_field_name_v1({
              name: __q.right_table_attribute,
              type: 'join',
              table_name: __q.table_name,
            });
            query = query.innerJoin(__q.table_name, function () {
              this.on(left_table_attribute, '=', right_table_attribute);
            });
          } else if (__q.join_type === 'left_join') {
            const left_table_attribute = get_field_name_v1({
              name: __q.left_table_attribute,
              type: 'join',
              table_name: options.table_name,
            });

            const right_table_attribute = get_field_name_v1({
              name: __q.right_table_attribute,
              type: 'join',
              table_name: __q.table_name,
            });
            query = query.leftJoin(__q.table_name, function () {
              this.on(left_table_attribute, '=', right_table_attribute);
            });
          }

          // push join fields here
          _.map(__q.fields, function (__q_f) {
            fields.push(
              get_field_name_v1({
                name: __q_f.name,
                type: 'join',
                table_name: __q.table_name,
                alias: true,
              })
            );

            fields_v1.push({
              name: get_field_name_v1({
                name: __q_f.name,
                type: 'join',
                table_name: __q.table_name,
                alias: true,
              }),
              readable_key: __q_f.readable_key,
            });
          });
        });

        _.map(taql.filters, function (__q) {
          const _q = {};
          const op = _.get(__q, 'op', 'eq');

          if (op === 'range') {
            if (_.size(_.get(__q, 'values', [])) !== 2) {
              throw new app.libs.customError('2 values should be passed in case of range queries', 400);
            }
            const __v = _.get(__q, 'values', []);
            query = query.whereBetween(get_field_name(__q), [__v[0], __v[1]]);
          } else if (op === 'isnull') {
            query.whereNull(get_field_name(__q));
          } else if (allowed_ops.indexOf(_.get(__q, 'op', 'eq')) > 1) {
            if (_.get(__q, 'value', 'NA') === 'NA') {
              // return reject(new app.libs.customError("value is required in case of range queries", 400))
              throw new app.libs.customError(`value is required in case of '${op}' queries`, 400);
            }
            // query = query.andWhere(get_field_name(__q), allowed_ops_map[op], __q.value)

            if (_.get(__q, 'op', 'eq') === 'like') {
              query = query.andWhere(get_field_name(__q), allowed_ops_map[op], `%${__q.value}%`);
            } else {
              query = query.andWhere(get_field_name(__q), allowed_ops_map[op], __q.value);
            }
          } else if (_.get(__q, 'values', 'NA') !== 'NA') {
            // query = query.whereIn(get_field_name(__q), __q.values)

            if (_.get(__q, 'op', 'eq') === 'ne') {
              query = query.whereNotIn(get_field_name(__q), __q.values);
            } else {
              query = query.whereIn(get_field_name(__q), __q.values);
            }
          } else {
            query = query.andWhere(get_field_name(__q), allowed_ops_map[op], __q.value);
          }
        });

        if (!_.isEmpty(_.get(taql, 'aggregations_v1', {}))) {
          const __aggregation = _.get(taql, 'aggregations_v1.aggregations', []);
          const __feilds_to_show = _.get(taql, 'aggregations_v1.fields', []);

          _.map(__aggregation, function (__q) {
            query = query.groupBy(get_field_name(__q));
          });

          const __with_agg = [];
          const __all_keys = [];
          for (const __a of __feilds_to_show) {
            if (__a.agg) {
              __with_agg.push(__a);
              continue;
            } else {
              const __key_to_display = `${get_field_name(__a)} as ${__a.name}`;
              __all_keys.push(__key_to_display);
            }
          }

          for (const __a of __with_agg) {
            switch (__a.agg) {
              case 'sum':
                query = query.sum(`${get_field_name(__a)} as ${get_field_name_v1(__a)}____${__a.agg}`);
                break;
              case 'avg':
                query = query.avg(`${get_field_name(__a)} as ${get_field_name_v1(__a)}____${__a.agg}`);
                break;
              case 'min':
                query = query.min(`${get_field_name(__a)} as ${get_field_name_v1(__a)}____${__a.agg}`);
                break;
              case 'max':
                query = query.max(`${get_field_name(__a)} as ${get_field_name_v1(__a)}____${__a.agg}`);
                break;
              default:
                query = query.count(`${get_field_name(__a)} as ${get_field_name_v1(__a)}____${__a.agg}`);
                break;
            }
          }

          const __data = await query
            .debug()
            .select(__all_keys)
            .count(`${get_field_name({ name: 'account_id' })} as document_____count`);
          return resolve({ data: __data });
        }
        _.map(taql.aggregations, function (__q) {
          query = query.groupBy(get_field_name(__q));
        });

        // code here
        if (_.size(taql.aggregations) > 0) {
          const __all_keys = [];
          for (const __a of taql.aggregations) {
            __all_keys.push(get_field_name(__a));
          }
          const __data = await query
            .debug()
            .select(__all_keys)
            .count(`${get_field_name({ name: 'account_id' })} as count`);
          return resolve({ data: __data });
        }

        const __count_q = query.clone();
        let __count = await __count_q.debug().count({ my_all_record_count: '*' });
        __count = app.libs.utils.checkFirstRecord(__count);
        __count = _.get(__count, 'my_all_record_count');

        _.map(taql.sort, function (__q) {
          if (__q.random === true) {
            query = query.orderByRaw('RAND()');
          } else {
            query = query.orderBy(get_field_name(__q), __q.order);
          }
          // query = query.orderBy(get_field_name(__q), __q.order)
        });

        if (_.get(taql, 'pagination')) {
          if (_.get(taql, 'pagination.page_size')) {
            query = query.limit(_.get(taql, 'pagination.page_size'));
          }

          if (_.get(taql, 'pagination.page_num')) {
            const from = _.get(taql, 'pagination.page_size') * (_.get(taql, 'pagination.page_num', 1) - 1);
            query = query.offset(from);
          }
        }

        if (_.get(taql, 'other_options.count_only') === 'true' || _.get(taql, 'other_options.count_only') === true) {
          return resolve({
            total: __count,
            data: [],
            export_to_excel: _.get(taql, 'other_options.export_to_excel'),
            fields,
          });
        }

        const __data = await query.debug().select(fields);
        _.map(__data, function (__d) {
          delete __d.my_all_record_count;
        });
        return resolve({
          total: __count,
          data: __data,
          export_to_excel: _.get(taql, 'other_options.export_to_excel'),
          fields,
          fields_v1,
        });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'taql_parser_and_search',
          options,
        });
      }
    });
  };

  db.delete_record_by_ID_or_UUID = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }

        const q = app.knex(options.table_name);

        q.where(options.identifier, options.id);
        q.delete();
        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            console.log('error in delete_record_by_ID_or_UUID ', err, 'options', options);
            return reject(new app.libs.customError(app.constants.error_message, 500));
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'delete_record_by_ID_or_UUID',
          options,
        });
      }
    });
  };

  db.delete_records = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }

        if (!options.where) {
          return reject(new app.libs.customError('please pass a valid where', 400));
        }

        const where_length = Object.keys(_.get(options, 'where', {}));
        // test this - code here
        if (_.isEmpty(options.where) || _.size(where_length) === 0) {
          return reject(new app.libs.customError('please pass a valid where', 400));
        }

        const q = app.knex(options.table_name);
        const and_where = false;
        for (const clause in _.get(options, 'where', {})) {
          if (!and_where) {
            q.where(clause, _.get(options, ['where', clause], 'NA'));
          } else {
            q.andWhere(clause, _.get(options, ['where', clause], 'NA'));
          }
        }

        q.delete();
        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            console.log('error in delete_record_by_ID_or_UUID ', err, 'options', options);
            return reject(new app.libs.customError(app.constants.error_message, 500));
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'delete_record_by_ID_or_UUID',
          options,
        });
      }
    });
  };

  db.delete_multiple_record_by_UUID = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.table_name) {
          return reject(new app.libs.customError('please pass a valid table_name', 400));
        }

        if (!_.size(options.uuids)) {
          return reject(new app.libs.customError('please pass a valid uuid', 400));
        }

        if (!options.workspace_uuid) {
          return reject(new app.libs.customError('please pass a valid workspace uuid', 400));
        }

        const q = app.knex(options.table_name);

        q.whereIn('uuid', options.uuids);
        q.andWhere('workspace_uuid', options.workspace_uuid);
        q.delete();
        q.debug().then(
          function (_res) {
            return resolve(_res);
          },
          function (err) {
            console.log('error in delete_multiple_record_by_UUID ', err, 'options', options);
            return reject(new app.libs.customError(app.constants.error_message, 500));
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'delete_record_by_ID_or_UUID',
          options,
        });
      }
    });
  };

  return db;
};
