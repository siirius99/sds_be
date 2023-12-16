const _ = require('lodash');
const uuid = require('uuid');

module.exports = function (app) {
  const wrapper = {};
  // return app.libs.error_handler.non_controller_handler({'e':e,'reject':reject,'function_name':'getRecord','options':options})
  wrapper.non_controller_handler = function (options) {
    try {
      const { e } = options;
      if ((e && e.status === 400) || e.status === 403 || e.status === 405 || e.status === 410) {
        return options.reject(new app.libs.customError(e.message, e.status));
      }
      app.log.error(`error in ${options.function_name} 'options: ', ${options}, 'error: ', ${options.e}`);
      return options.reject(new app.libs.customError(e.message, e.status));
    } catch (e) {
      app.log.error(`error in non_controller_handler ${e} 'options: ', ${options}, 'error: ', ${options.e}`);
      return options.reject(new app.libs.customError(app.constants.error_message, 500));
    }
  };

  // return app.libs.error_handler.controller_handler({ 'e': e, 'res': res, 'function_name': 'fee_bulk_template', 'query': req.query, 'body': req.body, 'params': req.params })
  wrapper.controller_handler = function (options) {
    try {
      const { e } = options;
      const { res } = options;
      if (e && e.status === 410) {
        return res.status(400).jsonp(app.libs.utils.parseIntoJson(e.message));
      }
      if (e && (e.status === 400 || e.status === 403 || e.status === 405 || e.status === 409)) {
        return res.status(e.status || 400).jsonp({ message: e.message });
      }
      app.log.error(
        `error in ${options.function_name}, query: ${JSON.stringify(options.query)}, body: ${JSON.stringify(
          options.body
        )}, params: ${JSON.stringify(options.params)}, error: ${options.e}`
      );
      return res.status(e.status || 500).jsonp({ message: app.constants.error_message });
    } catch (e) {
      app.log.error(`error in non_controller_handler ${e} 'options: ', ${options}, 'error: ', ${options.e}`);
      return options.reject(new app.libs.customError(app.constants.error_message, 500));
    }
  };

  return wrapper;
};
