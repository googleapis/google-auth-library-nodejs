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
var utils = require('./utils/url.js');

/**
 * The publically exposed url interface invokes its constituent options reducers
 * in the correct order.
 * @function generateUrl
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the user-provided options object
 * @returns {Object} - returns a new object which forms an amalgam of the
 *  originally provided generatedOptions and any applicable properties parsed or
 *  extracted from the user-provided givenOptions.
 */
function generateUrl (generatedOptions, givenOptions) {
  return utils.extractUrlComponents(
    utils.isUsingHttps(
      utils.createUrlObject(
        utils.extractRawHref(generatedOptions, givenOptions)
      )
    )
  );
}

module.exports = generateUrl;
