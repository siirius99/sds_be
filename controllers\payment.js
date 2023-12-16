const _ = require('lodash');
const uuid = require('uuid');
const Joi = require('@hapi/joi');
const moment = require('moment');
const momenttz = require('moment-timezone');

module.exports = function (app) {
  const controller = {};

  controller.get_stripe_payment_methods = async function (req, res, next) {
    try {
      const { stripe_customer_id, stripe_subscription_id } = await app.libs.utils.check_stripe_configured({
        user_info: req.user_info,
      });
      const __cards = await app.libs.payment.get_stripe_customer_payment_methods({
        stripe_customer_id,
        stripe_subscription_id,
      });
      return res.jsonp({ data: __cards });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_stripe_payment_methods',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.create_stripe_session_for_card = async function (req, res, next) {
    try {
      const { id, stripe_customer_id } = await app.libs.utils.check_stripe_configured({
        user_info: req.user_info,
      });
      const __session_uuid = uuid.v4();
      const {
        err,
        url: redirect_url,
        stripe_checkout_session_id,
      } = await app.libs.payment.create_stripe_session_for_card({
        uuid: __session_uuid,
        stripe_customer_id,
      });
      if (err) {
        return res.send('Can not add card');
      }
      const __to_update = {
        payment_method_session_id: __session_uuid,
        payment_method_data: app.libs.utils.parseIntoString({
          payment_method_checkout_session_id: stripe_checkout_session_id,
        }),
      };
      await app.db.update_record_by_ID_or_UUID({
        table_name: 'user_payment_status',
        id,
        identifier: 'id',
        update: __to_update,
      });
      return res.jsonp({ url: redirect_url });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'create_stripe_session_for_card',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.handle_payment_method_success_callback = async function (req, res, next) {
    try {
      const { session_id } = req.query;
      const { success } = await app.libs.payment.handle_payment_method_success_callback({ session_id });
      if (success) {
        const __url = `${app.config.ui_url}/membership?tab=cards&op=success`;
        return res.redirect(__url);
      }

      const __fail_url = `${app.config.ui_url}/membership?tab=cards&op=failed`;
      return res.redirect(__fail_url);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'handle_payment_method_success_callback',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.handle_payment_method_failure_callback = async function (req, res, next) {
    try {
      return res.redirect(`${app.config.ui_url}/membership?tab=cards&op=failed`);
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'handle_payment_method_failure_callback',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.update_stripe_payment_details = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          uuid: Joi.string().required(),
        }),
        data: req.params,
      });
      const { id, stripe_customer_id } = await app.libs.utils.check_stripe_configured({
        user_info: req.user_info,
      });
      await app.libs.payment.check_payment_method_exist_for_workspace({
        id: _.get(req, 'params.uuid', 'NA'),
        stripe_customer_id,
      });

      const __session_uuid = uuid.v4();
      const {
        err,
        url: redirect_url,
        stripe_checkout_session_id,
      } = await app.libs.payment.create_stripe_session_for_card({
        uuid: __session_uuid,
        stripe_customer_id,
      });
      if (err) {
        return res.send('Can not update card');
      }
      const __payment_method_data = {
        payment_method_checkout_session_id: stripe_checkout_session_id,
        update_payment_method_id: _.get(req, 'params.uuid'),
      };
      const __to_update = {
        payment_method_session_id: __session_uuid,
        payment_method_data: app.libs.utils.parseIntoString(__payment_method_data),
      };
      await app.db.update_record_by_ID_or_UUID({
        table_name: 'user_payment_status',
        id,
        identifier: 'id',
        update: _.merge(__to_update, app.libs.utils.get_basic_insert_details({ meta: { update: true } })),
      });
      return res.jsonp({ url: redirect_url });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'update_stripe_payment_details',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.delete_stripe_payment_method = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          uuid: Joi.string().required(),
        }),
        data: req.params,
      });
      const { stripe_customer_id } = await app.libs.utils.check_stripe_configured({ user_info: req.user_info });
      await app.libs.payment.check_payment_method_exist_for_workspace({
        id: _.get(req, 'params.uuid', 'NA'),
        stripe_customer_id,
        mode: 'delete',
      });
      await app.libs.payment.delete_stripe_payment_method({ user_info: req.user_info, id: _.get(req, 'params.uuid', 'NA') });

      return res.jsonp({ message: 'Card deleted successfully' });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'delete_stripe_payment_method',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.setup_default_payment_method = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          uuid: Joi.string().required(),
        }),
        data: req.params,
      });
      const { stripe_customer_id, stripe_subscription_id } = await app.libs.utils.check_stripe_configured({
        user_info: req.user_info,
      });
      await app.libs.payment.check_payment_method_exist_for_workspace({
        id: _.get(req, 'params.uuid', 'NA'),
        stripe_customer_id,
      });
      await app.libs.payment.update_default_stripe_payment_method({
        id: _.get(req, 'params.uuid', 'NA'),
        stripe_customer_id,
        stripe_subscription_id,
      });

      return res.jsonp({ message: 'Card marked as default' });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'setup_default_payment_method',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  controller.get_stripe_invoice_details = async function (req, res, next) {
    try {
      await app.libs.validation.joi_validation_v1({
        schema: Joi.object().keys({
          id: Joi.string().required(),
        }),
        data: req.params,
      });

      const { stripe_customer_id } = await app.libs.utils.check_stripe_configured({ user_info: req.user_info });
      const __stripe_invoice_id = _.get(req.params, 'id', 'NA');
      const { invoice: invoiceDetail } = await app.libs.utils.fetch_invoice_detail_from_stripe({
        stripe_invoice_id: __stripe_invoice_id,
      });
      if (stripe_customer_id !== _.get(invoiceDetail, 'customer')) {
        throw new app.libs.customError('Please check invoice ID', 400);
      }
      return res.jsonp({
        invoiceURL: invoiceDetail.hosted_invoice_url,
      });
    } catch (e) {
      return app.libs.error_handler.controller_handler({
        e,
        res,
        function_name: 'get_stripe_invoice_details',
        query: req.query,
        body: req.body,
        params: req.params,
      });
    }
  };

  return controller;
};
