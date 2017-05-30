module.exports = {
  application: {
    origin: process.env.APPLICATION_ORIGIN || 'http://localhost:4200'
  },
  auth0: require('./auth0')
};
