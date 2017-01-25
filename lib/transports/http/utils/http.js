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

function getTransport (isUsingHttps) {
  if (isUsingHttps) {
    return https;
  }
  return http;
}


function attemptBodyParse (body) {
  try {
    return JSON.parse(body);
  } catch (e) {
    return body;
  }
}

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

module.exports = {
  wrapGivenCallback: wrapGivenCallback,
  attemptBodyParse: attemptBodyParse,
  generateErrorInformation: generateErrorInformation,
  getTransport: getTransport
};
