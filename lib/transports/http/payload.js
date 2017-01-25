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
var has = require('lodash.has');
var queryString = require('querystring');
var extractJsonData = require('./utils/payload.js').extractJsonData;

function generateRequestPayload (generatedOptions, givenOptions) {
  var out = generatedOptions;
  if (has(givenOptions, 'json')) {
    if ((givenOptions.json === true) && !givenOptions.form &&
      !givenOptions.body) {
        // User is requesting to set the application header but does not have
        // a request body, do not set a request payload
        // TODO add an explicit unit test for this
        // TODO add a mocked request using this form
        out = generatedOptions;
      }
    out = merge({}, generatedOptions, {
      requestPayload: {
        isJSON: true,
        payload: extractJsonData(givenOptions.json, givenOptions.body,
          givenOptions.form)
      }
    });
  } else if (has(givenOptions, 'form')) {
    out = merge({}, generatedOptions, {
      requestPayload: {
        isJSON: false,
        payload: queryString.stringify(givenOptions.form)
      }
    });
  }
  if (has(givenOptions, 'qs')) {
    out = merge({}, out, {
      requestPayload: {
        queryString: queryString.stringify(givenOptions.qs)
      }
    });
  }
  return out;
}

module.exports = generateRequestPayload;
