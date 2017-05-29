'use strict';

const settings = require('.');

module.exports.get = (event, context, callback) => {
  // return hand-picked settings.
  const response = {
    statusCode: 200,
    body: JSON.stringify({
      auth0: settings.auth0
    })
  };
  callback(null, response);
};
