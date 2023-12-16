module.exports = function (app) {
  app.get('/payment/methods', app.libs.middleware.is_payment_enabled(), app.payment_controller.get_stripe_payment_methods);

  app.post(
    '/payment/create_checkout_session',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.create_stripe_session_for_card
  );

  app.get(
    '/payment/method/success',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.handle_payment_method_success_callback
  );

  app.get(
    '/payment/method/failure',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.handle_payment_method_failure_callback
  );

  app.put(
    '/:uuid/payment/method',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.update_stripe_payment_details
  );

  app.delete(
    '/:uuid/payment/method',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.delete_stripe_payment_method
  );

  app.put(
    '/:uuid/default/payment/method',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.setup_default_payment_method
  );

  app.get(
    '/sinvoice/:id/details',
    app.libs.middleware.is_payment_enabled(),
    app.payment_controller.get_stripe_invoice_details
  );
};
