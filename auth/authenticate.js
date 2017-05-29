const jsonwebtoken = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');

const settings = require('../settings');
const auth0 = settings.auth0;

const jwksClient = jwksRsa({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `https://${auth0.domain}/.well-known/jwks.json`
});

// Policy helper function
// http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html#api-gateway-custom-authorizer-output
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
// http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
module.exports.authenticate = (event, context, cb) => {
  if (!event.authorizationToken) {
    return cb('Unauthorized');
  }

  // Remove "Bearer " from token.
  const token = event.authorizationToken.substring(7);

  // Get kid, key id, from token header. This does not verify token.
  const decodedToken = jsonwebtoken.decode(token, {complete: true}) || {};
  const header = decodedToken.header || {};
  const kid = header.kid || '';

  // Get signing key from jwks uri.
  jwksClient.getSigningKey(kid, (err, key) => {
    if (err) {
      return cb(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    const options = {
      algorithms: ['RS256'],
      audience: auth0.clientId,
      issuer: `https://${auth0.domain}/`
    };
    // Verify token using public signing key.
    jsonwebtoken.verify(token, signingKey, options, (err, decoded) => {
      if (err) {
        cb('Unauthorized');
      } else {
        cb(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
      }
    });
  });
};
