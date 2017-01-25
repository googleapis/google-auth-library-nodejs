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

var utils = require('./utils/headers.js');

/**
 * Invokes the headers constituent functions in correct order to augment the
 * generatedOptions with header information about the request.
 * @function generateHeaders
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the user-provided request options
 * @return {Object} - returns a new object which is an amalgam of originally
 *  given generatedOptions and any necessary header information.
 */
function generateHeaders (generatedOptions, givenOptions) {
  return utils.addPostMethodHeaders(
    utils.addRequestMethod(
      utils.addUserAgentHeaders(
        utils.extractGivenHeaders(generatedOptions, givenOptions)
      ),
      givenOptions
    ),
    givenOptions
  );
}

// Set the readonly method for user agent as publically exposed for testing
// purposes
generateHeaders.USER_AGENT = utils.USER_AGENT;

module.exports = generateHeaders;
