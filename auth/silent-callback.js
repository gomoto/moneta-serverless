'use strict';

const settings = require('../settings');
const auth0 = settings.auth0;

module.exports.get = (event, context, callback) => {
  // Dynamic html.
  const html = `
  <!DOCTYPE html>
  <html>
    <head>
      <script src="https://cdn.auth0.com/js/auth0/8.7.0/auth0.min.js"></script>
      <script type="text/javascript">
        var auth0 = new auth0.WebAuth({
          clientID: '${auth0.clientId}',
          domain: '${auth0.domain}'
        });
        auth0.parseHash(window.location.hash, function (err, result) {
          parent.postMessage(err || result, '${settings.application.origin}');
        });
      </script>
    </head>
    <body></body>
  </html>
  `;

  const response = {
    statusCode: 200,
    headers: {
      'Content-Type': 'text/html'
    },
    body: html
  };
  callback(null, response);
};
