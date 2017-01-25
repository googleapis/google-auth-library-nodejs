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
var url = require('url');
var isString = require('lodash.isstring');
var merge = require('lodash.merge');
var has = require('lodash.has');

/**
 * Constant to check for https protocol designation in user-provided hrefs.
 * @constant
 * @type {RegExp}
 * @default
 */
var CHECK_FOR_HTTPS = /https/i;

/**
 * Basic error describing that the urlObject was not found on the
 * generatedOptions instance. Certain url util functions require this property
 * to operate.
 * @function InvalidUrlObjectError
 * @returns {Undefined} - does not return anything
 */
function InvalidUrlObjectError () {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = 'Unable to find urlObject property in generatedOptions';
}

/**
 * Basic error describing that the href property was not found on the
 * generatedOptions instance. Certain url util functions require this property
 * to operate.
 * @function InvalidHrefError
 * @returns {Undefined} - does not return anything
 */
function InvalidHrefError () {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = 'Unable to find href property in generatedOptions';
}

/**
 * Attempts to locate and extract the fully qualified host and path from the
 * user-provided options. This path is not immediatley parsed, it is instead
 * copied to the href property in generatedOptions so that other reducers may
 * use the href for request options processing.
 * @function extractRawHref
 * @param {Object} generatedOptions - the options used to execute the request
 * @param {Object} givenOptions - the options given by the user
 * @returns {Object} - returns a new object forming an amalgam of both
 *  generatedOptions and the extracted href path if applicable
 */
function extractRawHref (generatedOptions, givenOptions) {
  switch (true) {
    case has(givenOptions, 'uri'):
      return merge({}, generatedOptions, {
        href: givenOptions.uri
      });
    case has(givenOptions, 'url'):
      return merge({}, generatedOptions, {
        href: givenOptions.url
      });
    default:
      return merge({}, generatedOptions, {
        href: null
      });
  }
}

/**
 * Attempts to create a parsed Url instance on generatedOptions derived from the
 * href property present on generatedOptions.
 * @function createUrlObject
 * @param {Object} generatedOptions - the options used to execute the request
 * @returns {Object} - returns a new object forming an amalgam of both
 *  generatedOptions and the parsed urlObject
 * @throws {InvalidHrefError} - will throw if the href property is not present
 *  on the generatedOptions object
 */
function createUrlObject (generatedOptions) {
  if (!isString(generatedOptions.href)) {
    throw new InvalidHrefError();
  }
  return merge({}, generatedOptions, {
    urlObject: url.parse(generatedOptions.href)
  });
}

/**
 * Attempts to match for https protocol preambles in the href property on the
 * generatedOptions object.
 * @function isUsingHttps
 * @param {Object} generatedOptions - the optiosn used to execute the request
 * @returns {Object} - returns a new object forming an amalgam of both
 *  generatedOptions and a boolean flag indicating whether or not to execute
 *  the request with https module.
 */
function isUsingHttps (generatedOptions) {
  if (!(generatedOptions.urlObject instanceof url.Url)) {
    throw new InvalidUrlObjectError();
  }
  return merge({}, generatedOptions, {
    isUsingHttps: CHECK_FOR_HTTPS.test(generatedOptions.urlObject.protocol)
  });
}

/**
 * Attempts to extract the parsed Url instance present on the given
 * generatedOptions.urlObject into an http compatible host/path object property
 * set.
 * @function extractUrlComponents
 * @param {Object} generatedOptions - the options used to execute the request
 * @returns {Object} - returns the a new object forming an amalgam of both
 *  generatedOptions and the urlObject-extracted host/path properties
 * @throws {InvalidUrlObjectError} - will throw if the urlObject property is not
 *  an instance of Url
 */
function extractUrlComponents (generatedOptions) {
  if (!(generatedOptions.urlObject instanceof url.Url)) {
    throw new InvalidUrlObjectError();
  }
  var queryString = '';
  if (has(generatedOptions, 'requestPayload') && 
    has(generatedOptions.requestPayload, 'queryString')) {
    queryString += '?'+generatedOptions.requestPayload.queryString;
  }
  return merge({}, generatedOptions, {
    requestOptions: {
      host: generatedOptions.urlObject.host,
      path: generatedOptions.urlObject.path+queryString
    }
  });
}

module.exports = {
  extractUrlComponents: extractUrlComponents,
  isUsingHttps: isUsingHttps,
  extractRawHref: extractRawHref,
  createUrlObject: createUrlObject
};
