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
var merge = require('lodash.merge');
var isString = require('lodash.isstring');
var pkg = require('../../../../package.json');

/**
 * The user agent string constant that will be sent with every request.
 * @constant
 * @type {String}
 * @default
 */
var USER_AGENT = 'google-api-nodejs-client/'+pkg.version;

/**
 * The available content-types that can be sent via request with a body.
 * @constant
 * @type {Object<String>}
 * @default
 */
var CONTENT_TYPES = {
  json: 'application/json',
  form: 'application/x-www-form-urlencoded'
};

/**
 * The request methods that can, by spec, have a body attached to them.
 * @constant
 * @type {Array<String>}
 * @default
 */
var BODY_REQUESTS = ['POST', 'PUT', 'PATCH'];

/**
 * Merges the given options headers field, if applicable, into the
 * generatedOptions object. Any headers given as request options will then
 * be sent along with the request being formulated.
 * @function extractGivenHeaders
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the options given by the user at invocation
 * @returns {Object} - returns a new object which is the amalgam of both the
 *  generatedOptions content and the givenOptions' headers.
 */
function extractGivenHeaders (generatedOptions, givenOptions) {
  if (givenOptions.headers) {
    return merge({}, generatedOptions, {
      requestOptions: {
         headers: givenOptions.headers
      }
    });
  }
  return generatedOptions;
}

/**
 * Merges the default or given request method into the request options used to
 * execute the request.
 * @function addRequestMethod
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the user-provided request options
 * @return {Object} - return a new object which contains the amalgam of the
 *  given generatedOptions and either a user-provided method or the default
 *  method if no method is provided: GET
 */
function addRequestMethod (generatedOptions, givenOptions) {
  return merge({}, generatedOptions, {
    requestOptions: {
      method: isString(givenOptions.method) ?
        givenOptions.method.toUpperCase() : 'GET'
    }
  });
}

/**
 * Given that the request-to-execute has a payload which requires headers
 * describing the content of the payload this function will return a set of
 * generatedOptions which contain the correct headers for the payload being
 * sent in the request.
 * @function addPostMethodHeaders
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the user-provided request options
 * @return {Object} - returns a new object which, if applicable, is an amalgam
 * of the generatedOptions and any content headers required to describe the
 * payload of the request.
 */
function addPostMethodHeaders (generatedOptions, givenOptions) {
  var hasBody = BODY_REQUESTS
    .indexOf(generatedOptions.requestOptions.method) > -1;
  if (hasBody === true) {
    return merge({}, generatedOptions, {
      hasBody: hasBody,
      requestOptions: {
        headers: {
          'Content-Type': generatedOptions.requestPayload.isJSON ?
            CONTENT_TYPES.json : CONTENT_TYPES.form,
          'Content-Length': Buffer.byteLength(
            generatedOptions.requestPayload.payload)
        }
      }
    });
  } else if (!hasBody && givenOptions && (givenOptions.json === true)) {
    // TODO: add an explicit unit test for this branch
    return merge({}, generatedOptions, {
      requestOptions: {
        headers: {
          'Content-Type': CONTENT_TYPES.json
        }
      }
    });
  }
  return merge({}, generatedOptions, {hasBody: hasBody});
}

/**
 * Merges the user-agent headers of google-auth-library into the request options
 * used to execute the request.
 * @function addUserAgentHeaders
 * @param {Object} generatedOptions - the options used to execute the request
 * @returns {Object} - returns a new object which contains the amalgam of the
 *  given generatedOptions and the header that the google-auth-library uses.
 */
function addUserAgentHeaders (generatedOptions) {
  return merge({}, generatedOptions, {
    requestOptions: {
      headers: {
        'User-Agent': USER_AGENT
      }
    }
  });
}


module.exports = {
  extractGivenHeaders: extractGivenHeaders,
  addUserAgentHeaders: addUserAgentHeaders,
  addRequestMethod: addRequestMethod,
  addPostMethodHeaders: addPostMethodHeaders,
  USER_AGENT: function () {
    return USER_AGENT;
  }
};

