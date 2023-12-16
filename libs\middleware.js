const jwt = require('jsonwebtoken');
const _ = require('lodash');

module.exports = function (app) {
  const wrapper = {};

  wrapper.authenticate = function (req, res, next) {
    return new Promise(async function (resolve, reject) {
      try {
        // let go if it's a sessionless (tokenless) req like login
        let __flag = false;
        for (const __session_less_api of _.get(app.constants, 'session_less_apis', [])) {
          if (__session_less_api.URL === req.path && __session_less_api.METHOD === req.method) {
            __flag = true;
            break;
          }
        }

        if (__flag) {
          return next();
        }

        // TODO authentication
        const { token } = req.headers;
        const decoded = jwt.verify(token, app.config.secret);
        req.user_info = decoded;
        // fetch user details here for active/inactive
        const __user_id = _.get(req.user_info, 'user.id');
        if (__user_id === '-1') {
          return next();
        }
        if (__user_id) {
          const tableDetails = _.find(_.get(app.mysql_schema, 'tables'), (item) => item.tenant);
          if (!tableDetails) {
            return res.status(403).jsonp({ message: 'You are not allowed to access. Please contact support' });
          }
          const fieldDetails = _.get(tableDetails, 'external_fields') || {};
          const primaryKey = _.findKey(fieldDetails, { primary: true });
          const __user = await app.db.records({ table_name: tableDetails.name, [primaryKey]: __user_id });
          if (__user.length === 0) {
            return res.status(403).jsonp({ message: 'You are not allowed to access. Please contact support' });
          }
        } else {
          return res.status(403).jsonp({ message: 'You are not allowed to access. Please contact support' });
        }

        return next();
      } catch (e) {
        return res.status(403).jsonp({ message: 'Please pass a valid token' });
      }
    });
  };

  wrapper.is_payment_enabled = function () {
    return function (req, res, next) {
      try {
        if (app.libs.utils.is_payment_enabled()) {
          return next();
        }
        return res.status(404).jsonp({ message: 'Payment not enabled' });
      } catch (e) {
        return res.status(404).jsonp({ message: 'Payment not enabled' });
      }
    };
  };

  wrapper.is_root_user = function () {
    return function (req, res, next) {
      try {
        const __user_id = _.get(req.user_info, 'user.id');
        if (__user_id === '-1') {
          return next();
        }
        return res.status(401).json({ message: 'Unauthorized access' });
      } catch (e) {
        return res.status(401).json({ message: 'Unauthorized access' });
      }
    };
  };

  return wrapper;
};
