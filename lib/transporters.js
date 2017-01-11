/**
 * Copyright 2012 Google Inc. All Rights Reserved.
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
var url = require('url');
var queryString = require('querystring');
// var request = require('request'),
var merge = require('lodash.merge');
var isObject = require('lodash.isobject');
var pkg = require('../package.json');
var checkForHttps = /https/;

function extractUrlComponentsFromString (urlObject, opts) {
  return merge({}, opts, {
    host: urlObject.host,
    path: urlObject.path
  });
}

function isUsingHttps (urlObject) {
  if (!isObject(urlObject)) {
    return false;
  }
  return checkForHttps.test(urlObject.protocol);
}

function extractRequestPayload (opts) {
  if (isObject(opts.form)) {
    return JSON.stringify(opts.form);
  } else if (isObject(opts.json)) {
    return JSON.stringify(opts.json);
  }
  return '';
}

/**
 * Default transporter constructor.
 * Wraps request and callback functions.
 */
function DefaultTransporter() {}

/**
 * Default user agent.
 */
DefaultTransporter.prototype.USER_AGENT =
  'google-api-nodejs-client/' + pkg.version;

/**
 * Configures request options before making a request.
 * @param {object} opts Options to configure.
 * @return {object} Configured options.
 */
DefaultTransporter.prototype.configure = function(opts) {
  // set transporter user agent
  var query, parsedUrl;
  var isPosting = opts.method === 'POST';
  var requestPayload = null;
  opts.headers = opts.headers || {};
  if (!opts.headers['User-Agent']) {
    opts.headers['User-Agent'] = this.USER_AGENT;
  } else if (opts.headers['User-Agent'].indexOf(this.USER_AGENT) === -1) {
    opts.headers['User-Agent'] = opts.headers['User-Agent'] + ' ' + this.USER_AGENT;
  }
  if (opts.uri) {
    parsedUrl = url.parse(opts.uri);
    opts = extractUrlComponentsFromString(parsedUrl, opts);
    delete opts.uri;
  } else if (opts.url) {
    parsedUrl = url.parse(opts.url);
    opts = extractUrlComponentsFromString(parsedUrl, opts);
    delete opts.url;
  }
  if (opts.qs) {
    query = queryString.stringify(opts.qs);
    opts.path += '?'+query;
    delete opts.qs;
  }
  if (isPosting && opts.json) {
    requestPayload = extractRequestPayload(opts);
    opts.headers = merge({}, opts.headers, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(requestPayload)
    });
  }
  return {
    usingHttps: isUsingHttps(parsedUrl),
    requestOptions: opts,
    isPosting: isPosting,
    requestPayload: requestPayload
  };
};

/**
 * Makes a request with given options and invokes callback.
 * @param {object} opts Options.
 * @param {Function=} opt_callback Optional callback.
 * @return {Request} Request object
 */
DefaultTransporter.prototype.request = function(opts, opt_callback) {
  var config = this.configure(opts);
  var transport = config.usingHttps ? https : http;
  var data = '';
  var didError = false;
  var cb = this.wrapCallback_(opt_callback);
  var req = transport.request(config.requestOptions, function (response) {
    response.on('data', function (chunk) {
      data += chunk;
    });
    response.on('end', function () {
      if (didError) {
        return;
      } else if (response.statusCode !== 200) {
        cb(null, response, data);
        return;
      }
      cb(null, response, data);
    });
    response.on('error', function (err) {
      didError = true;
      cb(err, response, null);
    });
  });
  if (config.isPosting) {
    req.write(config.requestPayload);
  }
  req.end();
};

/**
 * Wraps the response callback.
 * @param {Function=} opt_callback Optional callback.
 * @return {Function} Wrapped callback function.
 * @private
 */
DefaultTransporter.prototype.wrapCallback_ = function(opt_callback) {
  return function(err, res, body) {
    if (err || !body) {
      return opt_callback && opt_callback(err, body, res);
    }
    // Only and only application/json responses should
    // be decoded back to JSON, but there are cases API back-ends
    // responds without proper content-type.
    try {
      body = JSON.parse(body);
    } catch (err) { /* no op */ }

    if (body && body.error && res.statusCode !== 200) {
      if (typeof body.error === 'string') {
        err = new Error(body.error);
        err.code = res.statusCode;

      } else if (Array.isArray(body.error.errors)) {
        err = new Error(body.error.errors.map(
                         function(err) { return err.message; }
                       ).join('\n'));
        err.code = body.error.code;
        err.errors = body.error.errors;

      } else {
        err = new Error(body.error.message);
        err.code = body.error.code || res.statusCode;
      }

      body = null;

    } else if (res.statusCode >= 500) {
      // Consider all '500 responses' errors.
      err = new Error(body);
      err.code = res.statusCode;
      body = null;
    }

    if (opt_callback) {
      opt_callback(err, body, res);
    }
  };
};

/**
 * Exports DefaultTransporter.
 */
module.exports = DefaultTransporter;
