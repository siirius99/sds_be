const _ = require('lodash');

module.exports = function (app) {
  app.get('/crud/:table_name', app.crud_controller.get);
  app.post('/crud/:table_name', app.crud_controller.post);
  app.get('/schema', app.crud_controller.get_schema);
  app.post('/login', app.crud_controller.login);
  app.delete('/crud/:table_name/:id', app.crud_controller.delete);
  app.put('/crud/:table_name/:id', app.crud_controller.update);
  app.get('/download/postman_collection', app.crud_controller.download_postman_collection);
};
