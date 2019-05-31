'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const uuid = require('uuid/v4');

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
  authkey: {type: String},
});

users.pre('save', function(next) {
  bcrypt
    .hash(this.password, 10)
    .then((hashedPassword) => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {
  if (!email) {
    return Promise.reject('Validation Error');
  }

  return this.findOne({ email })
    .then((user) => {
      if (!user) {
        throw new Error('User Not Found');
      }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch((error) => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({ username, password, email });
    });
};

users.statics.authenticateToken = function(token) {
  let decryptedToken;
  let verifyOptions = {};

  if (process.env.EXPIRATION) {
    switch (process.env.EXPIRATION.toLowerCase()) {
      case '15m':
        verifyOptions.maxAge = '30s';
        break;
      case '1h':
      case '60m':
        verifyOptions.maxAge = '1h';
        break;
    }
  }

  try {
    decryptedToken = jwt.verify(token, process.env.SECRET, verifyOptions);
  } catch (error) {
    console.log('token expired!');
    return error;
  }

  const query = { _id: decryptedToken.id };
  return this.findOne(query).then(authenticatedUser => {

  if (decryptedToken.singleUseKey) {
    console.log({authenticatedUser});
    let userKey = authenticatedUser.authkey;
    console.log({ userKey });
  }
  });
};

users.statics.authenticateBasic = function(auth) {
  let query = { username: auth.username };
  return this.findOne(query)
    .then((user) => user && user.comparePassword(auth.password))
    .catch((error) => {
      throw error;
    });
};

users.methods.comparePassword = function(password) {
  return bcrypt
    .compare(password, this.password)
    .then((valid) => (valid ? this : null));
};

users.methods.generateToken = function() {
  let token = {
    id: this._id,
    role: this.role,
  };

  let signOptions = {};

  if (process.env.EXPIRATION) {
    switch (process.env.EXPIRATION.toLowerCase()) {
      case '15m':
        signOptions.expiresIn = '30s';
        break;
      case '1h':
      case '60m':
        signOptions.expiresIn = '1h';
        break;
      case 'once':
      case 'one':
      case 'single':
      case 'oneuse':
        // this.authkey = uuid();
        // token.singleUseKey = this.authkey;
        // this.save().catch(console.error);
        console.log('oneuse generatetoken');
    }
  }

  return jwt.sign(token, process.env.SECRET, signOptions);
};

module.exports = mongoose.model('users', users);
