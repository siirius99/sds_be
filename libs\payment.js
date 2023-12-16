const _ = require('lodash');

module.exports = function (app) {
  const wrapper = {};
  const __stripe = require('stripe')(app.config.payment.stripe_secret_key);

  wrapper.get_stripe_customer_payment_methods = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __customer = await __stripe.customers.retrieve(_.get(options, 'stripe_customer_id'));
        let __default_payment_method = _.get(__customer, 'invoice_settings.default_payment_method', null);
        if (!__default_payment_method && _.get(options, 'stripe_subscription_id')) {
          // setup default payment method from subscription
          const __subscription = await __stripe.subscriptions.retrieve(_.get(options, 'stripe_subscription_id'));
          if (_.get(__subscription, 'default_payment_method')) {
            __default_payment_method = _.get(__subscription, 'default_payment_method');
            await __stripe.customers.update(_.get(options, 'stripe_customer_id'), {
              invoice_settings: { default_payment_method: __default_payment_method },
            });
          }
        }
        const __cards_info = [];
        await __stripe.paymentMethods
          .list({ customer: _.get(options, 'stripe_customer_id'), type: 'card' })
          .autoPagingEach((__card) => {
            const __info = _.pick(__card, ['id', 'billing_details', 'type', 'created']);
            const __card_details = _.pick(_.get(__card, 'card', {}), ['brand', 'country', 'exp_month', 'exp_year', 'last4']);
            const __is_default = __default_payment_method === __card.id;
            __cards_info.push({ ...__info, ...__card_details, is_default: __is_default });
          });
        return resolve(__cards_info);
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'get_stripe_customer_payment_methods',
          options,
        });
      }
    });
  };

  wrapper.create_stripe_session_for_card = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __customer_id = _.get(options, 'stripe_customer_id');
        const __session_id = _.get(options, 'uuid');
        const __session = await __stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'setup',
          customer: __customer_id,
          cancel_url: `${app.config.app_url}/payment/method/failure?session_id=${__session_id}`,
          success_url: `${app.config.app_url}/payment/method/success?session_id=${__session_id}`,
          billing_address_collection: 'required',
        });
        return resolve({ url: __session.url, stripe_checkout_session_id: __session.id });
      } catch (e) {
        return resolve({ err: e });
      }
    });
  };

  wrapper.check_payment_method_exist_for_workspace = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __stripe_customer_id = _.get(options, 'stripe_customer_id');
        const __requested_id = _.get(options, 'id');
        const __cards = await app.libs.payment.get_stripe_customer_payment_methods({
          stripe_customer_id: __stripe_customer_id,
        });
        const __found = _.find(__cards, { id: __requested_id });
        if (!__found) {
          throw new app.libs.customError('Payment method not found', 400);
        }
        if (_.get(options, 'mode') === 'delete' && __found.is_default) {
          throw new app.libs.customError('Default payment method cannot be deleted', 400);
        }
        if (_.get(options, 'mode') === 'delete' && _.size(__cards) === 1) {
          throw new app.libs.customError('Single payment method cannot be deleted', 400);
        }
        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'check_payment_method_exist_for_workspace',
          options,
        });
      }
    });
  };

  wrapper.delete_stripe_payment_method = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        await __stripe.paymentMethods.detach(_.get(options, 'id'));
        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'delete_stripe_payment_method',
          options,
        });
      }
    });
  };

  wrapper.update_default_stripe_payment_method = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        await __stripe.subscriptions.update(_.get(options, 'stripe_subscription_id'), {
          default_payment_method: _.get(options, 'id'),
        });
        await __stripe.customers.update(_.get(options, 'stripe_customer_id'), {
          invoice_settings: { default_payment_method: _.get(options, 'id') },
        });
        return resolve();
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'update_default_stripe_payment_method',
          options,
        });
      }
    });
  };

  wrapper.handle_payment_method_success_callback = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const { session_id } = options;
        if (!session_id) {
          return resolve({});
        }
        let __existing_record = await app.db.records({
          table_name: 'user_payment_status',
          payment_method_session_id: session_id,
        });
        if (_.size(__existing_record) === 0) {
          return resolve({});
        }
        [__existing_record] = __existing_record;
        const __payment_method_data = app.libs.utils.parseIntoJson(__existing_record.payment_method_data || '{}');
        const __update_payment_method_id = _.get(__payment_method_data, 'update_payment_method_id');
        if (__update_payment_method_id) {
          const __cards = await app.libs.payment.get_stripe_customer_payment_methods({
            stripe_customer_id: __existing_record.stripe_customer_id,
          });
          const __found = _.find(__cards, { id: __update_payment_method_id });
          if (__found) {
            const __session = await __stripe.checkout.sessions.retrieve(
              _.get(__payment_method_data, 'payment_method_checkout_session_id', null)
            );
            const __setupIntent = await __stripe.setupIntents.retrieve(_.get(__session, 'setup_intent', null));
            const __payment_method = _.get(__setupIntent, 'payment_method');
            const __is_card_default = __found.is_default;
            if (__is_card_default) {
              await app.libs.payment.update_default_stripe_payment_method({
                id: __payment_method,
                stripe_customer_id: __existing_record.stripe_customer_id,
                stripe_subscription_id: __existing_record.stripe_subscription_id,
              });
            }
            // delete
            await app.libs.payment.delete_stripe_payment_method({ id: __update_payment_method_id });
          }
        }

        return resolve({ success: true });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'handle_payment_method_success_callback',
          options,
        });
      }
    });
  };

  return wrapper;
};
