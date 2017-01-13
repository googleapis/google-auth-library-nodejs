/**
 * Copyright 2016 Google Inc. All Rights Reserved.
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
var pkg = require('../../../package.json');

var USER_AGENT = 'google-api-nodejs-client/'+pkg.version;
var CONTENT_TYPES = {
  json: 'application/json',
  form: 'application/x-www-form-urlencoded'
};
var BODY_REQUESTS = ['POST', 'PUT', 'PATCH'];

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

function addUserAgentHeaders (generatedOptions) {
  return merge({}, generatedOptions, {
    requestOptions: {
      headers: {
        'User-Agent': USER_AGENT
      }
    }
  });
}

function addRequestMethod (generatedOptions, givenOptions) {
  return merge({}, generatedOptions, {
    requestOptions: {
      method: isString(givenOptions.method) ?
        givenOptions.method.toUpperCase() : 'GET'
    }
  });
}

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

function generateHeaders (generatedOptions, givenOptions) {
  return addPostMethodHeaders(addRequestMethod(addUserAgentHeaders(
    extractGivenHeaders(generatedOptions, givenOptions)), givenOptions),
    givenOptions);
}

module.exports = {
  extractGivenHeaders: extractGivenHeaders,
  addUserAgentHeaders: addUserAgentHeaders,
  addRequestMethod: addRequestMethod,
  addPostMethodHeaders: addPostMethodHeaders,
  generateHeaders: generateHeaders,
  USER_AGENT: USER_AGENT
};
