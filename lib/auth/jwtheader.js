/**
 * Copyright 2015 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var jws = require('jws');

/**
 * JWTHeader service account credentials.
 *
 * Create a new access token by using the credential to create a new JWT token
 * that's recognized as the access token.
 *
 * @param {string=} email the service account email address.
 * @param {string=} key the private key that will be used to sign the token.
 * @constructor
 */
function JWTHeader(email, key) {
  this.email = email;
  this.key = key;
}

/**
 * Executes the given callback if it is not null.
 *
 * Is used to simplify invocation of optional callbacks.
 */
function maybeCall_(c, err, res) {
  if (c) {
    c(err, res);
  }
}

/**
 * Indicates whether the credential requires scopes to be created by calling
 * createdScoped before use.
 *
 * @return {boolean} always false
 */
JWTHeader.prototype.createScopedRequired = function() {
  // JWT Header authentication does not use scopes.
  return false;
};

/**
 * Get a non-expired access token, after refreshing if necessary
 *
 * @param {string} authURI the URI being authorized
 * @param {function} accessTokenFn a callback invoked with the access
 *                   token.
 */
JWTHeader.prototype.refreshAccessToken = function(authURI, accessTokenFn) {
  var that = this;
  var iat = Math.floor(new Date().getTime() / 1000);
  var exp = iat + 3600; // 3600 seconds = 1 hour

  // The payload used for signed JWT headers has:
  // iss == sub == <client email>
  // aud == <the authorization uri>
  var payload = {
    iss: this.email,
    sub: this.email,
    aud: authURI,
    exp: exp,
    iat: iat
  };
  var assertion = {
    header: {
      alg: 'RS256',
      typ: 'JWT'
    },
    payload: payload,
    secret: this.key
  };

  // Sign the jwt and invoke accessTokenFn with it.
  this._signJWT(assertion, function(err, signedJWT) {
    if (!err) {
      accessTokenFn(null, {access_token: signedJWT});
    } else {
      accessTokenFn(err, null);
    }
  });
};

/**
 * Create a JWTHeader credentials instance using the given input options.
 * @param {object=} json The input object.
 * @param {function=} opt_callback Optional callback.
 */
JWTHeader.prototype.fromJSON = function(json, opt_callback) {
  var that = this;
  if (!json) {
    maybeCall_(opt_callback, new Error(
      'Must pass in a JSON object containing the service account auth settings.'));
    return;
  }
  if (!json.client_email) {
    maybeCall_(opt_callback, new Error(
      'The incoming JSON object does not contain a client_email field'));
    return;
  }
  if (!json.private_key) {
    maybeCall_(opt_callback, new Error(
      'The incoming JSON object does not contain a private_key field'));
    return;
  }
  // Extract the relevant information from the json key file.
  that.email = json.client_email;
  that.key = json.private_key;
  maybeCall_(opt_callback);
};

/**
 * Create a JWTHeader credentials instance using the given input stream.
 * @param {object=} stream The input stream.
 * @param {function=} opt_callback Optional callback.
 */
JWTHeader.prototype.fromStream = function(stream, opt_callback) {
  var that = this;
  if (!stream) {
    process.nextTick(function() {
      maybeCall_(
        opt_callback,
        new Error('Must pass in a stream containing the service account auth settings.'));
    });
    return;
  }
  var s = '';
  stream.setEncoding('utf8');
  stream.on('data', function (chunk) {
    s += chunk;
  });
  stream.on('end', function () {
    try {
      var data = JSON.parse(s);
      that.fromJSON(data, opt_callback);
    } catch (err) {
      maybeCall_(opt_callback, err);
    }
  });
};

/**
 * Sign the JWT object, returning any errors in the callback.
 *
 * signedJwtFn is a callback function(err, signedJWT); it is called with an
 * error if there is an exception during signing.
 *
 * @param  {object}   assertion   The assertion to sign
 * @param  {Function} signedJwtFn  fn(err, signedJWT)
 */
JWTHeader.prototype._signJWT = function(assertion, signedJwtFn) {
  try {
    signedJwtFn(null, jws.sign(assertion));
  } catch (err) {
    signedJwtFn(err);
  }
};

/**
 * Export JWTHeader.
 */
module.exports = JWTHeader;
