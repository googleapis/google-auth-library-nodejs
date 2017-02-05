/**
 * Copyright 2017 Google Inc. All Rights Reserved.
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
var https = require('https');
var http = require('http');
var isFunction = require('lodash.isfunction');
var isString = require('lodash.isstring');
var isObject = require('lodash.isobject');
var noOp = require('lodash.noop');
var has = require('lodash.has');

/**
 * Function to provide configuration-based switching of core http library for
 * both secured and unsecured requests.
 * @param {Boolean} isUsingHttps - whether or not to return the https module
 *  instead of the http module
 * @returns {http|https} - either the http or https module based on input
 */
function getTransport (isUsingHttps) {
  if (isUsingHttps) {
    return https;
  }
  return http;
}

/**
 * Function to isolate mechanics of request body parsing attempt. All responses
 * are generally checked for a body since some replies are not to spec from
 * specific services.
 * @param {Any} body - the body to attempt to parse to JSON
 * @returns {Any|Object} - returns either the original argument if unable to
 *  parse to JSON or returns the parsed JSON object if successful.
 */
function attemptBodyParse (body) {
  try {
    return JSON.parse(body);
  } catch (e) {
    return body;
  }
}

/**
 * Error decoration function which maintains legacy compatibility API with
 * consuming modules. If an error occurred during the request/response lifecycle
 * and a google-specific error response body is provided this function will
 * attempt to augment the error-back Error instance with specific components of
 * the response.
 * @param {Any} body - the response body
 * @param {Response} res - the http/s response instance
 * @returns {Null|Error} - returns null if error processing information is
 *  inapplicable or an augmented Error instance if applicable
 */
function generateErrorInformation (body, res) {
  var err = null;
  if (isObject(body) && has(body, 'error') && res.statusCode !== 200) {
    if (isString(body.error)) {
      err = new Error(body.error);
      err.code = res.statusCode;
      return err;
    } else if (Array.isArray(body.error.errors)) {
      err = new Error(body.error.errors.map(
        function (err) {
          return err.message;
        }
      ).join('\n'));
      err.code = body.error.code;
      err.errors = body.error.errors;
      return err;
    }
    err = new Error(body.error.message);
    err.code = has(body.error, 'code') ? body.error.code : res.statusCode;
  } else if (res.statusCode >= 500) {
    err = new Error(body);
    err.code = res.statusCode;
  }
  return err;
}

/**
 * Legacy compatibility middleware which reorders argument callback order from
 * request completion to the original argument order that google-auth-library
 * originally exposed to all consumers. Also attempts to decorate any error
 * information, if applicable, by calling generateErrorInformation.
 * @param {Any} cb - The user-provided callback
 * @returns {Undefined} - does not return anything
 */
function wrapGivenCallback (cb) {
  if (!isFunction(cb)) {
    return noOp;
  }
  return function (err, res, body) {
    var parsedBody, parsedError;
    if (err || !body) {
      return cb(err, body, res);
    }
    parsedBody = attemptBodyParse(body);
    parsedError = generateErrorInformation(parsedBody, res);
    if (parsedError) {
      parsedBody = null;
    }
    cb(parsedError, parsedBody, res);
  };
}

module.exports = {
  wrapGivenCallback: wrapGivenCallback,
  attemptBodyParse: attemptBodyParse,
  generateErrorInformation: generateErrorInformation,
  getTransport: getTransport
};
