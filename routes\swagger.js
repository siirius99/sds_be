const fs = require('fs');
const swaggerUi = require('swagger-ui-express');
const _ = require('lodash');

const __sql_type_mapper = {
  integer: 'integer',
  boolean: 'integer',
  string: 'string',
  guid: 'guid',
  decimal: 'number',
  datetime: 'number',
};

const __pg_type_mapper = {
  smallint: 'integer',
  integer: 'integer',
  decimal: 'number',
  varchar: 'string',
  uuid: 'string',
  boolean: 'boolean',
  date: 'string',
  serial: 'integer',
  numeric: 'number',
  text: 'string',
};

module.exports = function (app) {
  let __mapper = {};
  if (app.config.client === 'pg') {
    __mapper = __pg_type_mapper;
  } else {
    __mapper = __sql_type_mapper;
  }

  function mapSQLToSwaggerType(type) {
    return __mapper[type.toLowerCase()] || 'unknown';
  }

  const swaggerOptions = {
    openapi: '3.0.0',
    info: {
      title: 'Project Documentation',
      version: '1.0.0',
      description: 'API documentation for your JSON APIs',
    },
    paths: {},
    components: {
      securitySchemes: {
        JWT: {
          type: 'apiKey',
          name: 'token',
          in: 'header',
        },
      },
    },
    security: [{ JWT: [] }],
  };

  for (const item of app.mysql_schema.tables) {
    if (item.crud_get_enabled) {
      const path = `/crud/${item.name}`;
      if (!swaggerOptions.paths[path]) {
        swaggerOptions.paths[path] = {};
      }
      swaggerOptions.paths[path].get = {
        summary: `Get data from ${item.name}`,
        description: `Get data from ${item.name}`,
        responses: {
          200: {
            description: 'Success',
          },
        },
      };
    }
    if (item.crud_post_enabled) {
      const path = `/crud/${item.name}`;
      if (!swaggerOptions.paths[path]) {
        swaggerOptions.paths[path] = {};
      }
      const reqBody = {};
      const requireFields = [];
      for (const column of _.get(item, 'columns') || []) {
        const __m = _.get(item, ['external_fields', column]);
        if (!__m.primary && !__m.session) {
          reqBody[column] = {
            type: mapSQLToSwaggerType(_.get(__m, 'data_type')),
          };
          if (_.get(__m, 'required')) {
            requireFields.push(column);
          }
        }
      }

      swaggerOptions.paths[path].post = {
        summary: `Save data to ${item.name}`,
        description: `Save data to ${item.name}`,
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: reqBody,
                required: requireFields,
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Resource created successfully',
          },
          400: {
            description: 'Bad Request',
          },
          500: {
            description: 'Internal Server Error',
          },
        },
      };
    }

    if (item.crud_put_enabled) {
      const path = `/crud/${item.name}/{id}`;
      if (!swaggerOptions.paths[path]) {
        swaggerOptions.paths[path] = {};
      }
      const reqBody = {};
      const requireFields = [];
      const parameters = [
        {
          in: 'path',
          name: 'id',
          required: true,
          schema: {
            type: 'string',
          },
        },
      ];

      for (const column of _.get(item, 'columns') || []) {
        const __m = _.get(item, ['external_fields', column]);
        if (__m.alterable) {
          reqBody[column] = {
            type: mapSQLToSwaggerType(_.get(__m, 'data_type')),
          };
          if (_.get(__m, 'required')) {
            requireFields.push(column);
          }
        }
      }
      const requestBody = {
        in: 'body',
        name: 'body',
        description: 'Request body',
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: reqBody,
              required: requireFields,
            },
          },
        },
      };

      swaggerOptions.paths[path].put = {
        summary: `Update data of ${item.name}`,
        description: `Update data of ${item.name}`,
        parameters,
        requestBody,
        responses: {
          200: {
            description: 'Resource updated successfully',
          },
          400: {
            description: 'Bad Request',
          },
          404: {
            description: 'Record not found',
          },
          500: {
            description: 'Internal Server Error',
          },
        },
      };
    }

    if (item.crud_delete_enabled || item.crud_soft_delete_enabled) {
      const path = `/crud/${item.name}/{id}`;
      if (!swaggerOptions.paths[path]) {
        swaggerOptions.paths[path] = {};
      }

      let __primary_key = '';
      const parameters = [];
      for (const column of _.get(item, 'columns') || []) {
        const __m = _.get(item, ['external_fields', column]);
        if (__m.primary) {
          parameters.push({
            name: column,
            required: true,
            in: 'path',
            description: column,
            schema: {
              type: mapSQLToSwaggerType(_.get(__m, 'data_type')),
            },
          });
          __primary_key = column;
          break;
        }
      }
      swaggerOptions.paths[path].delete = {
        summary: `${item.crud_soft_delete_enabled ? 'Archive' : 'Delete'} ${item.name} by ${__primary_key}`,
        description: `${item.crud_soft_delete_enabled ? 'Archive' : 'Delete'} ${item.name} by ${__primary_key}`,
        parameters,
        responses: {
          200: {
            description: `Successful ${item.crud_soft_delete_enabled ? 'archived' : 'deleted'}`,
          },
          404: {
            description: 'Record not found',
          },
        },
      };
    }
  }
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerOptions));
};
