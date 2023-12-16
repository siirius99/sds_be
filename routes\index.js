const express = require('express');

module.exports = function (app) {
  app.post(
    '/create_checkout_session',
    app.libs.middleware.is_payment_enabled(),
    app.index_controller.create_checkout_session
  );
  app.get('/payment_status', app.libs.middleware.is_payment_enabled(), app.index_controller.payment_status);
  app.get('/success_callback', app.libs.middleware.is_payment_enabled(), app.index_controller.payment_success);
  app.get('/failure_callback', app.libs.middleware.is_payment_enabled(), app.index_controller.payment_failure);
  app.post(
    '/stripe_webhook',
    app.libs.middleware.is_payment_enabled(),
    express.raw({ type: 'application/json' }),
    app.index_controller.stripe_webhook
  );
  app.get(
    '/subscription/invoices',
    app.libs.middleware.is_payment_enabled(),
    app.index_controller.fetch_subscription_invoices
  );
  app.get('/project_meta', app.index_controller.get_project_meta);
  app.post('/signup', app.index_controller.register_user);
  app.get('/client/kpi', app.libs.middleware.is_root_user(), app.index_controller.get_user_kpi_info);
  app.get('/client/info', app.libs.middleware.is_root_user(), app.index_controller.get_user_info);
  app.put('/client/info', app.libs.middleware.is_root_user(), app.index_controller.update_client_info);
  app.get('/version', app.index_controller.get_app_version);
};
