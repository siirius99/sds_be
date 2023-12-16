const _ = require('lodash');
const Joi = require('@hapi/joi');
const moment = require('moment');
const bcrypt = require('bcrypt');
const packageJson = require('../package.json');

module.exports = function (app) {
  const controller = {};
  const __stripe = require('stripe')(app.config.payment.stripe_secret_key);
  controller.create_checkout_session = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          plan: Joi.string().valid('monthly', 'yearly').required(),
        }),
        data: req.body,
      });

      const __q1 = { table_name: 'user_payment_status' };
      __q1.user_uuid = _.get(req, ['user_info', 'user', 'id']);
      let __record = await app.db.records(__q1);

      if (_.size(__record) === 0) {
        throw new app.libs.customError('something went wrong', 400);
      }
      [__record] = __record;

      const session_id = `${moment().unix()}${parseInt(Math.random(1, 100) * 100, 10)}`;
      const allowed_trial_days = _.get(req, 'body.plan') === 'yearly' ? app.config.trial_period_days : 0;

      await app.db.update_record_by_ID_or_UUID({
        table_name: 'user_payment_status',
        id: __record.id,
        identifier: 'id',
        update: _.merge(
          {
            session_id,
            plan: _.get(req, 'body.plan'),
            allowed_trial_days,
          },
          app.libs.utils.get_basic_insert_details({ meta: { update: true }, user_info: req.user_info })
        ),
      });

      let { stripe_customer_id } = __record;
      if (!__record.stripe_customer_id) {
        if (!__record.email) {
          throw new app.libs.customError(`Email not found in user_payment_status for ID: ${__record.id}`, 400);
        }

        const stripe_cust_resp = await app.libs.utils.create_customer_in_stripe({ email: __record.email });

        stripe_customer_id = stripe_cust_resp.customer.id;

        await app.db.update_record_by_ID_or_UUID({
          table_name: 'user_payment_status',
          id: __record.id,
          identifier: 'id',
          update: _.merge(
            {
              stripe_customer_id,
            },
            app.libs.utils.get_basic_insert_details({ meta: { update: true }, user_info: req.user_info })
          ),
        });
      }

      if (!stripe_customer_id) {
        throw new app.libs.customError(
          `Stripe subscription ID not found in user_payment_status for ID: ${__record.id}`,
          400
        );
      }

      const { app_url } = app.config;
      const __days_left = allowed_trial_days;
      const __product = app.config.payment.product[req.body.plan];
      const payload = {
        mode: 'subscription',
        payment_method_types: ['card'],
        customer: stripe_customer_id,
        line_items: [
          {
            price: __product.price_id,
            quantity: 1,
          },
        ],
        success_url: `${app_url}/success_callback?session_id=${session_id}`,
        cancel_url: `${app_url}/failure_callback`,
      };

      if (__days_left > 0) {
        payload.subscription_data = {
          trial_period_days: __days_left,
        };
      }

      const session = await __stripe.checkout.sessions.create(payload);

      return res.jsonp({
        url: session.url,
      });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'create_checkout_session',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.payment_status = async function (req, res, next) {
    try {
      const __resp = await app.libs.utils.check_user_payment_status({ user_info: req.user_info });
      return res.jsonp(__resp);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'payment_status',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.payment_success = async function (req, res, next) {
    try {
      let resp = req.query;
      if (typeof resp === 'string') {
        resp = app.libs.utils.parseIntoJson(resp);
      }

      const { session_id } = resp;
      if (!session_id) {
        throw new app.libs.customError(app.constants.error_message, 500);
      }

      // fetch customer ID based on this session_id &
      const __q1 = { table_name: 'user_payment_status' };
      __q1.session_id = session_id;
      let __record = await app.db.records(__q1);

      if (_.size(__record) === 0) {
        throw new app.libs.customError(app.constants.error_message, 500);
      }
      [__record] = __record;

      const subscriptions = await __stripe.subscriptions.list({
        customer: __record.stripe_customer_id,
      });

      if (_.size(_.get(subscriptions, 'data')) === 0) {
        throw new app.libs.customError(app.constants.error_message, 500);
      } else {
        const stripe_subscription_id = _.get(subscriptions, 'data.0.id');
        if (!stripe_subscription_id) {
          throw new app.libs.customError(app.constants.error_message, 500);
        }

        await app.db.update_record_by_ID_or_UUID({
          table_name: 'user_payment_status',
          id: __record.id,
          identifier: 'id',
          update: {
            payment_done: 1,
            stripe_subscription_id,
            subscription_status: _.get(subscriptions, 'data.0.status', null),
            subscription_status_updated_timestamp: moment().unix(),
            plan_type: 'paid',
          },
        });
        await app.libs.utils.update_user_subscriber_info({ stripe_subscription_id, uuid: __record.uuid });

        // add default card for customer
        const __default_payment_method = _.get(subscriptions, 'data.0.default_payment_method', null);
        await __stripe.customers.update(__record.stripe_customer_id, {
          invoice_settings: { default_payment_method: __default_payment_method },
        });
      }

      const __url = `${app.config.ui_url}/payment_success`;
      return res.redirect(__url);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'payment_success',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.payment_failure = async function (req, res, next) {
    try {
      const __url = `${app.config.ui_url}/payment_failure`;
      return res.redirect(__url);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'payment_failure',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.stripe_webhook = async function (req, res, next) {
    try {
      const endpointSecret = app.config.payment.stripe_webhook_key;
      const sig = req.headers['stripe-signature'];
      let event;
      try {
        event = __stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
        res.status(200).end();
      } catch (err) {
        app.log.error(`error on stripe_webhook error: ${err}`);
        res.status(400).send(`Webhook Error: ${err.message}`);
        return;
      }
      await app.libs.utils.sleep(1500);
      await app.libs.utils.handle_stripe_webhook({ event });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'stripe_webhook',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.fetch_subscription_invoices = async function (req, res, next) {
    try {
      const { stripe_customer_id } = await app.libs.utils.check_stripe_configured({ user_info: req.user_info });
      const { invoices } = await app.libs.utils.fetch_all_invoices_from_stripe({
        stripe_customer_id,
      });
      function check_invoice_type({ invoice }) {
        const res = { type: 'Paid' };
        try {
          if (invoice.total < 0) {
            res.type = 'Credited';
          } else if (invoice.amount_due > 0 || invoice.total === 0) {
            res.type = 'Paid';
          } else {
            res.type = 'Debited';
          }
        } catch (e) {
          app.log.error(`Error in check_invoice_type for invoice: ${invoice}. Error: ${e && e.message}`);
        }
        return res;
      }
      const __data = [];
      for (const invoice of _.get(invoices, 'data', [])) {
        const invoice_type = check_invoice_type({ invoice });
        const invoice_payload = {
          stripe_invoice_id: invoice.id,
          amount_in_cents: Math.abs(invoice.total),
          hosted_invoice_url: invoice.hosted_invoice_url,
          invoice_pdf_url: invoice.invoice_pdf,
          status: invoice.status,
          currency: invoice.currency,
          paid: invoice.paid ? 1 : 0,
          invoice_created_at: invoice.created,
          invoice_paid_at: _.get(invoice, 'status_transitions.paid_at'),
          quantity: _.get(invoice, 'lines.data.0.quantity'),
        };
        if (invoice_type && invoice_type.type) invoice_payload.type = invoice_type.type;
        if (invoice_type && invoice_type.type === 'Paid') invoice_payload.amount_in_cents = Math.abs(invoice.amount_due);
        __data.push(invoice_payload);
      }
      return res.jsonp({ data: __data });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'fetch_subscription_invoices',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_project_meta = async function (req, res, next) {
    try {
      return res.jsonp({ payment_configured: app.libs.utils.is_payment_enabled() });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_project_meta',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.register_user = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          name: Joi.string().required(),
          email: Joi.string()
            .email({
              minDomainSegments: 2,
            })
            .required(),
          password: Joi.string().required(),
          utm_trial: Joi.number(),
        }),
        data: req.body,
      });

      const __table_details = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
      if (!__table_details) {
        throw new app.libs.customError('Registration is currently closed. We apologize for any inconvenience.', 403);
      }
      const __primary_key = _.findKey(_.get(__table_details, 'external_fields') || {}, { primary: true });
      if (!__primary_key) {
        throw new app.libs.customError('Registration is currently closed. We apologize for any inconvenience.', 403);
      }
      const __where_cl = { table_name: __table_details.name, email: _.get(req.body, 'email') };
      let __result = await app.db.records(_.cloneDeep(__where_cl));
      if (__result.length !== 0) {
        throw new app.libs.customError('User already exists. Please login with your existing credentials.', 409);
      }
      const __salt = await bcrypt.genSalt(app.config.__salt_rounds);
      const __hash = await bcrypt.hash(_.get(req, 'body.password'), __salt);

      const __payload = { password: __hash, email: _.get(req, 'body.email') };
      const __name = _.get(req.body, 'name').split(' ');
      let __name_key_exists = false;
      if (__table_details.columns.indexOf('name') !== -1) {
        __payload.name = _.get(req.body, 'name');
        __name_key_exists = true;
      } else if (__table_details.columns.indexOf('firstname') !== -1) {
        [__payload.firstname] = __name;
      }
      if (__table_details.columns.indexOf('lastname') !== -1) {
        if (__name_key_exists) [__payload.name] = __name;
        __payload.lastname = __name.slice(1).join(' ') || null;
      }
      const __record1 = _.merge(
        __payload,
        app.libs.utils.get_basic_insert_details({ user_info: req.user_info, table_name: __table_details.name })
      );
      await app.db.insert_record({ table_name: __table_details.name, record: __record1 });
      __result = await app.db.records(_.cloneDeep(__where_cl));
      if (app.libs.utils.is_payment_enabled()) {
        await app.libs.utils.check_user_payment_status({
          user_info: {
            user: {
              id: _.get(__result, [0, __primary_key]),
            },
          },
          trial_period_days: _.get(req, 'body.utm_trial', app.config.trial_period_days),
        });
      }
      const authDetails = await app.libs.auth.generate_token({ id: _.get(__result, [0, __primary_key]) });
      return res.jsonp(
        _.merge(authDetails, {
          user: { ...__result[0], is_admin: false },
          message: 'User registered successfully',
        })
      );
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'register_user',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_user_kpi_info = async function (req, res, next) {
    try {
      const __table_details = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
      if (!__table_details) {
        throw new app.libs.customError('Tenant not configured.', 403);
      }
      let __trials = 0;
      let __payment_done = 0;
      let __signup = { count: 0, configured: false };
      const __total_user_sql = `select count(*) as total_users from ${__table_details.name}`;
      const __total_user_res = await app.db.raw({ sql: __total_user_sql });

      if (app.libs.utils.is_payment_enabled()) {
        const __signup_sql = `select count(*) AS total from user_payment_status where created_timestamp >= ${moment()
          .startOf('month')
          .unix()}`;
        const __signup_sql_res = await app.db.raw({ sql: __signup_sql });
        __signup = { count: _.get(__signup_sql_res, 'data.0.total', 0), configured: true };

        const __trial_sql = `select payment_done, created_timestamp, allowed_trial_days from user_payment_status`;
        const __trial_sql_res = await app.db.raw({ sql: __trial_sql });
        for (const __d of _.get(__trial_sql_res, 'data', [])) {
          if (__d.payment_done === 0) {
            const __diff = moment().unix() - __d.created_timestamp;
            const __diff_days = __diff / (60 * 60 * 24);
            const __trial_days_left = __d.allowed_trial_days - parseInt(__diff_days, 10);
            if (__trial_days_left >= 0) {
              __trials += 1;
            }
          } else {
            __payment_done += 1;
          }
        }
      }
      const __data = {
        no_of_clients: _.get(__total_user_res, 'data.0.total_users', 0),
        no_of_paid_clients: __payment_done,
        no_of_trials: __trials,
        no_of_signups: __signup,
      };
      return res.jsonp(__data);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_user_kpi_info',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_user_info = async function (req, res, next) {
    try {
      if (!app.libs.utils.is_payment_enabled()) {
        return res.jsonp([]);
      }
      const __table_details = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
      if (!__table_details) {
        return res.jsonp([]);
      }
      const __primary_key = _.findKey(_.get(__table_details, 'external_fields') || {}, { primary: true });
      if (!__primary_key) {
        return res.jsonp([]);
      }

      const __taql = {
        filters: [],
        fields: [
          {
            name: 'name',
          },
          {
            name: __primary_key,
          },
        ],
        joins: [
          {
            table_name: 'user_payment_status',
            join_type: 'inner_join',
            left_table_attribute: __primary_key,
            right_table_attribute: 'user_uuid',
            fields: [
              {
                name: 'payment_done',
              },
              {
                name: 'email',
              },
              {
                name: 'created_timestamp',
              },
              {
                name: 'allowed_trial_days',
              },
              {
                name: 'subscription_status',
              },
              {
                name: 'plan_type',
              },
              {
                name: 'plan',
              },
            ],
          },
        ],
      };

      const __data = await app.db.taql_parser_and_search({
        table_name: __table_details.name,
        query: { taql: __taql },
        user_info: req.user_info,
      });
      for (const __d of _.get(__data, 'data', [])) {
        __d.payment_done = __d.user_payment_status__payment_done;
        __d.email = __d.user_payment_status__email;
        __d.created_timestamp = __d.user_payment_status__created_timestamp;
        __d.allowed_trial_days = __d.user_payment_status__allowed_trial_days;
        __d.plan_type = __d.user_payment_status__plan_type;
        __d.plan = __d.user_payment_status__plan;
        if (__d.payment_done === 0) {
          // check expiration
          const __diff = moment().unix() - __d.user_payment_status__created_timestamp;
          const __diff_days = __diff / (60 * 60 * 24);
          const __trial_days_left = __d.user_payment_status__allowed_trial_days - parseInt(__diff_days, 10);
          if (__trial_days_left < 0) {
            __d.trial_expired = 1;
            __d.account_status = 'Trial expired';
          } else {
            __d.trial_expired = 0;
            __d.trial_days_left = __trial_days_left;
            __d.account_status = 'Trial';
          }
        } else {
          __d.account_status = 'Active';
        }
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
        __d.payment_status = __d.user_payment_status__subscription_status
          ? __status_mapper[__d.user_payment_status__subscription_status]
            ? 'Paid'
            : 'Overdue'
          : null;
        __d.plan_details = __d.user_payment_status__plan
          ? _.pick(_.get(app.config, ['payment', 'product', __d.user_payment_status__plan], {}), [
              'actual_price',
              'currency',
            ])
          : {};
        delete __d.user_payment_status__payment_done;
        delete __d.user_payment_status__email;
        delete __d.user_payment_status__subscription_status;
        delete __d.user_payment_status__created_timestamp;
        delete __d.user_payment_status__allowed_trial_days;
        delete __d.user_payment_status__plan_type;
        delete __d.user_payment_status__plan;
      }
      return res.jsonp(_.get(__data, 'data', []));
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_user_info',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.update_client_info = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          uuid: Joi.string().required(),
          trial_days_left: Joi.number().integer().min(0),
        }),
        data: req.body,
      });

      const __q = { table_name: 'user_payment_status', user_uuid: _.get(req, ['body', 'uuid']) };
      let __res1 = await app.db.records(__q);
      if (_.size(__res1) === 0) {
        throw new app.libs.customError('Record not found', 400);
      }
      [__res1] = __res1;
      if (__res1.payment_done === 1) {
        throw new app.libs.customError('Access Denied: User subscription is already active', 400);
      }
      const __diff = moment().unix() - __res1.created_timestamp;
      const __diff_days = __diff / (60 * 60 * 24);
      const allowed_trial_days = __diff_days + _.get(req.body, 'trial_days_left', 0);

      await app.db.update_record_by_ID_or_UUID({
        table_name: 'user_payment_status',
        id: _.get(__res1, 'id', 'NA'),
        identifier: 'id',
        update: {
          allowed_trial_days: parseInt(allowed_trial_days, 10),
          trial_expired: 0,
        },
      });

      return res.jsonp({ message: 'Information updated successfully' });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'update_client_info',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_app_version = async function (req, res, next) {
    try {
      const { version } = packageJson;
      return res.jsonp({ version });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_app_version',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  return controller;
};
