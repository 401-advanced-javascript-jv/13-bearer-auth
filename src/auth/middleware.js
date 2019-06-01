'use strict';

const User = require('./users-model.js');
// const Role = require('./roles-model.js');

module.exports = (capability) => {
  return (request, response, next) => {
    try {
      let [authType, authString] = request.headers.authorization.split(/\s+/);

      switch (authType.toLowerCase()) {
      case 'basic':
        console.log('basic');
        return _authBasic(authString);
      case 'bearer':
        console.log('bearer');
        return _authBearer(authString);
      default:
        return _authError();
      }
    } catch (error) {
      next(error);
    }

    function _authBearer(token) {
      try {
        User.authenticateToken(token) // returns an authenticated user
          .then(_authenticate) // takes in an authenticated user
          .catch(next);
      } catch (error) {
        response.sendStatus(404);
      }
    }

    function _authBasic(str) {
      // str: am9objpqb2hubnk=
      let base64Buffer = Buffer.from(str, 'base64'); // <Buffer 01 02 ...>
      let bufferString = base64Buffer.toString(); // john:mysecret
      let [username, password] = bufferString.split(':'); // john='john'; mysecret='mysecret']
      let auth = { username, password }; // { username:'john', password:'mysecret' }

      return User.authenticateBasic(auth)
        .then((user) => _authenticate(user))
        .catch(next);
    }

    function _authenticate(user) {
      if (user) {
        request.user = user;
        request.token = user.generateToken();
        next();
      } else {
        _authError();
      }
    }

    function _authError() {
      next('Invalid');
    }
  };
};
