'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const uuid = require('uuid/v4');

const SECRET = process.env.SECRET;
const TOKEN_LIFETIME = process.env.TOKEN_LIFETIME || '15m';
const SINGLE_USE_TOKEN = !!process.env.SINGLE_USE_TOKEN;

const validTokens = new Set();

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
  authkey: { type: String },
});

users.virtual('capabilities', {
  ref: 'capabilities',
  localField: 'role',
  foreignField: 'role',
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
    .catch((_) => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({ username, password, email });
    });
};

users.statics.authenticateToken = function(token) {
  if (SINGLE_USE_TOKEN && validTokens.has(token)) {
    validTokens.delete(token);
    validTokens.add(this.generateToken());
  } else {
    return Promise.reject('invalid token');
  }

  let decryptedToken;

  try {
    decryptedToken = jwt.verify(token, SECRET);
  } catch (error) {
    return Promise.reject('invalid token');
  }

  const query = { _id: decryptedToken.id };
  return this.findOne(query);
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

users.methods.generateToken = function(type) {
  let token = {
    id: this._id,
    role: this.role,
    type: type || 'user',
  };

  let signOptions = {};

  if (!!TOKEN_LIFETIME && type !== 'key') {
    signOptions.expiresIn = TOKEN_LIFETIME;
  }

  if (type === 'key') {
    token.type = 'key';
  }

  let signedToken;
  try {
    signedToken = jwt.sign(token, SECRET, signOptions);
  } catch (error) {
    throw error;
  }

  if (SINGLE_USE_TOKEN) {
    validTokens.add(signedToken);
  }

  return signedToken;
};

module.exports = mongoose.model('users', users);
