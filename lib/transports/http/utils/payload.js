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
var isString = require('lodash.isstring');
var isObject = require('lodash.isobject');

/**
 * Attempts to locate and extract a request body from user provided options.
 * The request library allows for request options like the following:
 * {
 *   json: true,
 *   body: {
 *     param: 1
 *   }
 * }
 * Wherein the body must be parsed into JSON. This form produces the same result
 * as the following:
 * {
 *   json: {
 *     param: 1
 *   }
 * }
 * Whereas the following produces a query string as opposed to JSON-encoded
 * string due to the absence of the JSON flag
 * {
 *   body: {
 *    param: 1
 *   }
 * }
 * The output of the preceding, though, will be mirrored by the output of the
 * following:
 * {
 *   form: {
 *     param: 1
 *   }
 * }
 * @function extractJsonData
 * @param {Any} jsonProp - the givenOptions.json property
 * @param {Any} bodyProp - the givenOptions.body property
 * @param {Any} formProp - the givenOptions.form property
 * @returns {String} - returns either an empty or JSON encoded string
 */
function extractJsonData (jsonProp, bodyProp, formProp) {
  if (isString(jsonProp)) {
    return jsonProp;
  } else if (isObject(jsonProp)) {
    return JSON.stringify(jsonProp);
  } else if (jsonProp === true) {
    if (isObject(bodyProp)) {
      return JSON.stringify(bodyProp);
    } else if (isObject(formProp)) {
      return JSON.stringify(formProp);
    }
  }
  return '';
}

module.exports = {
  extractJsonData: extractJsonData
};
