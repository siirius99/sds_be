const _ = require('lodash');
const moment = require('moment');
const momenttz = require('moment-timezone');
const uuid = require('uuid');
const async = require('async');
const Joi = require('@hapi/joi');

module.exports = function (app) {
  const __stripe = require('stripe')(app.config.payment.stripe_secret_key);
  const utils = {};

  utils.checkFirstRecord = function (options) {
    if (options.length > 0) {
      return options[0];
    }
    return undefined;
  };

  // app.libs.utils.parseIntoJson()
  utils.parseIntoJson = function (value) {
    if (typeof value === 'object' && value != null) return value;
    let parsedValue;
    try {
      parsedValue = JSON.parse(value);
    } catch (e) {
      parsedValue = {};
    }
    if (!parsedValue) {
      parsedValue = {};
    }
    return parsedValue;
  };

  // app.libs.utils.complete_null_check()
  utils.complete_null_check = function (value) {
    if (_.isNull(value) || _.isUndefined(value) || _.isNaN(value)) {
      return false;
    }
    return true;
  };

  // app.libs.utils.pluckkeys(value, keys)
  utils.pluckkeys = function (value, keys) {
    if (typeof value !== 'object') {
      console.log('Not a object', value);
      return value;
    }
    const return_value = {};
    try {
      _.map(keys, function (__key) {
        return_value[__key] = value[__key];
      });
      return return_value;
    } catch (e) {
      console.log(':pluckkeys e', e);
    }

    return return_value;
  };

  // app.libs.utils.parseIntoString()
  utils.parseIntoString = function (value) {
    let stringValue;
    try {
      if (typeof value === 'string') {
        return value;
      }
      try {
        stringValue = JSON.stringify(value);
      } catch (e) {
        stringValue = '{}';
      }
      return stringValue;
    } catch (e) {
      console.log('error in parseIntoString value', value, 'error', e);
      return stringValue;
    }
  };

  // app.libs.utils.pluck(__all_new_cf_keys, 'uuid')
  utils.pluck = function (__list, key) {
    const _list_to_return = [];
    try {
      _.map(__list, function (__val) {
        _list_to_return.push(_.get(__val, key));
      });
      return _list_to_return;
    } catch (e) {
      console.log('error in pluck value', __list, 'key', key, 'error', e);
      return _list_to_return;
    }
  };

  // app.libs.utils.pluck_key_value(__all_new_cf_keys, ['uuid'])
  utils.pluck_key_value = function (__list, keys) {
    const _list_to_return = [];
    try {
      _.map(__list, function (__val) {
        const _o = {};
        _.map(keys, function (__key) {
          _o[__key] = __val[__key];
        });
        _list_to_return.push(_o);
      });
      return _list_to_return;
    } catch (e) {
      console.log('error in pluck_key_value', __list, 'key', keys, 'error', e);
      return _list_to_return;
    }
  };

  // app.libs.utils.remove_null(
  utils.remove_null = function (__list) {
    const _list_to_return = [];
    try {
      _.map(__list, function (__val) {
        if (__val !== null && __val !== undefined) _list_to_return.push(__val);
      });
      return _list_to_return;
    } catch (e) {
      console.log('error in pluck value', __list, 'error', e);
      return _list_to_return;
    }
  };

  // app.libs.utils.sleep(1000)
  utils.sleep = function (ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  };

  // let sorted = app.libs.utils.sort({ 'data': _.get(_class_b, ['date', 'buckets']), 'property':'key' })
  // asc order
  utils.sort = function (options) {
    options.data.sort(function (a, b) {
      return a[options.property] - b[options.property];
    });
    return options.data;
  };

  // app.libs.utils.sort_array({ 'data':''})
  utils.sort_array = function (options) {
    options.data.sort(function (a, b) {
      return a - b;
    });
    return options.data;
  };

  // app.libs.utils.sort_array({ 'data':''})
  utils.sort_array_by_length = function (options) {
    options.data.sort(function (a, b) {
      return a.length - b;
    });
    return options.data;
  };

  /*
        app.libs.utils.boolean({ 'value': 'value' })
    */

  utils.boolean = function (options) {
    if (_.get(options, 'value') === 'TRUE' || _.get(options, 'value') === 'true' || options.value === true) {
      return true;
    }
    return false;
  };

  utils.size = function (value) {
    return _.size(value);
  };

  /*
        TODO
    */
  utils.get_basic_insert_details = function (options) {
    const __to_return = {};
    const __crud_details = _.find(_.get(app.mysql_schema, ['tables']), {
      name: _.get(options, 'table_name'),
    });
    const __field_details = _.get(__crud_details, 'external_fields') || {};

    for (const __column in __field_details) {
      const __meta = __field_details[__column];
      if (__meta.session) {
        if (__meta.data_type === 'DateTime') {
          __to_return[__column] = moment().unix();
        } else {
          __to_return[__column] = _.get(options, ['user_info', 'user', 'id']) || -1;
        }
      }
    }

    if (_.get(options, 'meta.update') === true) {
      return __to_return;
    }

    const __primary_key = _.findKey(__field_details, { primary: true });
    const __primary_key_meta = _.get(__crud_details, ['external_fields', __primary_key], {});
    const __uuid_set = new Set(['guid', 'uuid']);
    if (__uuid_set.has(__primary_key_meta.data_type)) {
      __to_return[__primary_key] = uuid.v4();
    }
    return __to_return;
  };

  utils.execute_in_parallel = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        async.eachLimit(
          _.get(options, 'functions', []),
          5,
          function (__fn, cb) {
            if (_.get(__fn, 'name')) {
              const __fnc = _.get(app, _.get(__fn, 'name'));
              __fnc(__fn.options).then(
                function (__resp) {
                  __fn.res = __resp;
                  return cb();
                },
                function (err) {
                  return cb(err);
                }
              );
            } else {
              return cb();
            }
          },
          function (err, data) {
            if (err) {
              throw new err();
            }
            return resolve({ details: _.get(options, 'functions', []) });
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'execute_in_parallel',
          options,
        });
      }
    });
  };

  utils.get_default_column_set_for_export = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const table_columns = _.get(
          _.find(_.get(app.mysql_schema, ['tables']), { name: options.table_name }),
          'columns',
          []
        );
        const __internal_columns = ['id'];
        const __given_internal_columns = _.get(
          _.find(_.get(app.constants, ['mysql_schema', 'tables']), { name: options.table_name }),
          'internal_columns',
          __internal_columns
        );
        const __diff = _.difference(table_columns, __given_internal_columns);
        return resolve({ columns: __diff });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'get_default_column_set_for_export',
          options,
        });
      }
    });
  };

  utils.is_payment_enabled = function () {
    return _.get(app.config, 'payment_enabled') === true;
  };

  utils.check_user_payment_status = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        let __tables = _.get(app.mysql_schema, 'tables', []);
        __tables = _.find(__tables, function (o) {
          return o.tenant;
        });
        if (!__tables) {
          return reject(new Error('Tenant table not found'));
        }
        const __tenant_table_name = __tables.name;
        const __primary_key = _.findKey(_.get(__tables, 'external_fields') || {}, { primary: true });
        if (!__primary_key) {
          return reject(new Error('Primary key not configured'));
        }
        if (!_.get(options, ['user_info', 'user', 'id'])) {
          return reject(new Error('User id is required'));
        }
        const __q = { table_name: 'user_payment_status' };
        __q.user_uuid = _.get(options, ['user_info', 'user', 'id']);

        const __q_users = { table_name: [__tenant_table_name] };
        __q_users[__primary_key] = _.get(options, ['user_info', 'user', 'id']);
        __q_users.fields = ['email'];

        const __plans = Object.keys(app.config.payment.product).map((key) => ({
          name: app.config.payment.product[key].display,
          value: key,
          amount: parseInt(app.config.payment.product[key].actual_price, 10),
          text: app.config.payment.product[key].text,
          currency: app.config.payment.product[key].currency,
        }));

        const __resp_master = await app.libs.utils.execute_in_parallel({
          functions: [
            {
              name: 'db.records',
              options: __q,
              query_name: 'user_payment_status',
            },
            {
              name: 'db.records',
              options: __q_users,
              query_name: 'users',
            },
          ],
        });
        const __user_payment_status = _.find(_.get(__resp_master, 'details', []), function (o) {
          return _.get(o, 'query_name') === 'user_payment_status';
        });
        let __record = _.get(__user_payment_status, 'res', []);

        let __users = _.find(_.get(__resp_master, 'details', []), function (o) {
          return _.get(o, 'query_name') === 'users';
        });

        __users = _.get(__users, 'res', []);

        if (_.size(__record) === 0) {
          const __record1 = _.merge(
            {
              email: __users[0].email,
              plan_type: 'free',
              uuid: uuid.v4(),
              created_timestamp: moment().unix(),
              updated_timestamp: moment().unix(),
              user_uuid: _.get(options, ['user_info', 'user', 'id']),
              allowed_trial_days: _.get(options, 'trial_period_days') || app.config.trial_period_days,
            },
            app.libs.utils.get_basic_insert_details({ user_info: options.user_info, table_name: 'user_payment_status' })
          );
          await app.db.insert_record({ table_name: 'user_payment_status', record: __record1 });
          const __q1 = { table_name: 'user_payment_status' };
          __q1.user_uuid = _.get(options, ['user_info', 'user', 'id']);
          __record = await app.db.records(__q1);
          [__record] = __record;
        } else {
          [__record] = __record;
        }

        let __trial_expired = false;

        if (__record.plan_type === 'free') {
          const __diff = moment().unix() - _.get(__record, 'created_timestamp', moment().unix());
          const __diff_days = __diff / (60 * 60 * 24);
          const __days_left = __record.allowed_trial_days - parseInt(__diff_days, 10);
          if (__diff_days > __record.allowed_trial_days) {
            await app.db.update_record_by_ID_or_UUID({
              table_name: 'user_payment_status',
              id: __record.id,
              identifier: 'id',
              update: {
                trial_expired: 1,
              },
            });
            __trial_expired = true;
          }

          return resolve({
            show_banner: __record.allowed_trial_days - __diff_days <= 3,
            trial_expired: __trial_expired,
            days_left: __days_left,
            trial_days_left: __days_left,
            payment_done: false,
            subscription_status: __record.subscription_status,
            subscription_status_updated_timestamp: __record.subscription_status_updated_timestamp,
            trial_start_timestamp: __record.trial_start_timestamp,
            subscription_start_timestamp: __record.subscription_start_timestamp,
            next_payment_timestamp: __record.next_payment_timestamp,
            plan: __record.plan,
            plan_type: __record.plan_type,
            plans: __plans,
          });
        }

        return resolve({
          trial_expired: __trial_expired,
          payment_done: __record.payment_done === 1,
          subscription_status: __record.subscription_status,
          subscription_status_updated_timestamp: __record.subscription_status_updated_timestamp,
          trial_start_timestamp: __record.trial_start_timestamp,
          subscription_start_timestamp: __record.subscription_start_timestamp,
          next_payment_timestamp: __record.next_payment_timestamp,
          plan: __record.plan,
          plan_type: __record.plan_type,
          plans: __plans,
        });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'check_user_payment_status',
          options,
        });
      }
    });
  };

  utils.create_customer_in_stripe = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        await app.libs.validation.joi_validation_v1({
          schema: Joi.object().keys({
            email: Joi.string()
              .email({
                minDomainSegments: 2,
              })
              .required(),
          }),
          data: { email: options.email },
        });

        const customer = await __stripe.customers.create({
          email: options.email,
        });

        return resolve({ customer });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'create_customer_in_stripe',
          options,
        });
      }
    });
  };

  utils.update_user_subscriber_info = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __stripe_subscription_id = options.stripe_subscription_id;
        const __uuid = options.uuid;
        const __subscription = await __stripe.subscriptions.retrieve(__stripe_subscription_id);
        const __to_update = {
          trial_start_timestamp: _.get(__subscription, 'trial_start', null),
          subscription_start_timestamp: _.get(__subscription, 'start_date', null),
          next_payment_timestamp: _.get(__subscription, 'current_period_end', null),
        };
        await app.db.update_record_by_ID_or_UUID({
          table_name: 'user_payment_status',
          id: __uuid,
          identifier: 'uuid',
          update: _.merge(__to_update, app.libs.utils.get_basic_insert_details({ meta: { update: true } })),
        });
        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'update_user_subscriber_info',
          options,
        });
      }
    });
  };

  utils.execute_in_parallel = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        async.eachLimit(
          _.get(options, 'functions', []),
          5,
          function (__fn, cb) {
            if (_.get(__fn, 'name')) {
              const __fnc = _.get(app, _.get(__fn, 'name'));
              __fnc(__fn.options).then(
                function (__resp) {
                  __fn.res = __resp;
                  return cb();
                },
                function (err) {
                  return cb(err);
                }
              );
            } else {
              return cb();
            }
          },
          function (err, data) {
            if (err) {
              throw err;
            }
            return resolve({ details: _.get(options, 'functions', []) });
          }
        );
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'execute_in_parallel',
          options,
        });
      }
    });
  };

  utils.handle_stripe_webhook = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const { event } = options;
        switch (event.type) {
          case 'invoice.payment_action_required':
          case 'invoice.payment_failed':
          case 'invoice.payment_succeeded':
          case 'invoice.paid': {
            const __event_object = event.data.object;
            await app.libs.utils.handle_user_payment_status({ stripe_invoice_id: __event_object.id, context: event.type });
            break;
          }
          default:
            break;
        }
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'handle_stripe_success_callback',
          options,
        });
      }
    });
  };

  utils.fetch_invoice_detail_from_stripe = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const invoice = await __stripe.invoices.retrieve(options.stripe_invoice_id);
        return resolve({ invoice });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'fetch_invoice_detail_from_stripe',
          options,
        });
      }
    });
  };

  utils.handle_user_payment_status = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        let { stripe_customer_id } = options;
        if (!stripe_customer_id) {
          const { stripe_invoice_id } = options;
          const { invoice: invoiceDetail } = await app.libs.utils.fetch_invoice_detail_from_stripe({
            stripe_invoice_id,
          });

          stripe_customer_id = invoiceDetail.customer;
        }

        if (!stripe_customer_id) {
          return resolve();
        }

        const __q1 = { table_name: 'user_payment_status' };
        __q1.stripe_customer_id = stripe_customer_id;
        let __records = await app.db.records(__q1);

        if (!_.size(__records)) {
          return resolve();
        }

        [__records] = __records;
        if (!__records.stripe_subscription_id) {
          return resolve();
        }
        const __subscription = await __stripe.subscriptions.retrieve(__records.stripe_subscription_id);
        const __subscription_status = _.get(__subscription, 'status', 'NA');
        const __status_mapper = {
          active: 1,
          past_due: 0,
          unpaid: 0,
          canceled: 0,
          incomplete: 0,
          incomplete_expired: 0,
          trialing: 1,
          paused: 0,
        };
        const __status = __status_mapper[__subscription_status];
        if (__status === undefined) {
          return resolve();
        }
        const __to_update = {
          subscription_status: __subscription_status,
          subscription_status_updated_timestamp: moment().unix(),
        };

        await app.db.update_record_by_ID_or_UUID({
          table_name: 'user_payment_status',
          id: _.get(__records, 'id', 'NA'),
          identifier: 'id',
          update: __to_update,
        });

        await app.libs.utils.update_user_subscriber_info({
          stripe_subscription_id: __records.stripe_subscription_id,
          uuid: __records.uuid,
        });

        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'handle_user_payment_status',
          options,
        });
      }
    });
  };

  utils.check_stripe_configured = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __q = { table_name: 'user_payment_status' };
        __q.user_uuid = _.get(options, ['user_info', 'user', 'id']);
        let __record = await app.db.records(__q);

        if (_.size(__record) === 0) {
          throw new app.libs.customError('Subscription not found', 400);
        }
        [__record] = __record;
        if (!__record.stripe_customer_id) {
          throw new app.libs.customError('Subscription not found', 400);
        }
        return resolve(__record);
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'check_stripe_configured',
          options,
        });
      }
    });
  };

  utils.fetch_all_invoices_from_stripe = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        if (!options.stripe_customer_id) return resolve({ invoices: { data: [] } });
        const invoices = await __stripe.invoices.list({
          customer: options.stripe_customer_id,
          limit: 100,
        });
        return resolve({ invoices });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'fetch_all_invoices_from_stripe',
          options,
        });
      }
    });
  };
  return utils;
};
