const jwt = require('jsonwebtoken');

module.exports = function (app) {
  const wrapper = {};

  /*
        Function responsible for generating token
    */
  wrapper.generate_token = function (options) {
    return new Promise(async function (resolve, reject) {
      try {
        const __user_payload = { user: { id: options.id } };
        const token = jwt.sign(__user_payload, app.config.secret, {
          expiresIn: app.config.token_expiration_time,
        });

        return resolve({ token });
      } catch (e) {
        return app.libs.error_handler.non_controller_handler({
          e,
          reject,
          function_name: 'generate_token',
          options,
        });
      }
    });
  };
  return wrapper;
};
