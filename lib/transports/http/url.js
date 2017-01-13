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
var has = require('lodash.has');
var CHECK_FOR_HTTPS = /https/;
var url = require('url');
var Url = url.Url;

var INVALID_URL_OBJECT = 'Unable to find url object in generatedOptions';

function extractUrlComponents (generatedOptions) {
  if (!(generatedOptions.urlObject instanceof Url)) {
    throw new TypeError(INVALID_URL_OBJECT);
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

function isUsingHttps (generatedOptions) {
  if (!(generatedOptions.urlObject instanceof Url)) {
    throw new TypeError(INVALID_URL_OBJECT);
  }
  return merge({}, generatedOptions, {
    isUsingHttps: CHECK_FOR_HTTPS.test(generatedOptions.urlObject.protocol)
  });
}

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

function createUrlObject (generatedOptions) {
  if (!isString(generatedOptions.href)) {
    throw new TypeError('Cannot find valid href property');
  }
  return merge({}, generatedOptions, {
    urlObject: url.parse(generatedOptions.href)
  });
}

function generateUrl (generatedOptions, givenOptions) {
  return extractUrlComponents(isUsingHttps(createUrlObject(extractRawHref(
    generatedOptions, givenOptions))));
}

module.exports = {
  extractUrlComponents: extractUrlComponents,
  isUsingHttps: isUsingHttps,
  extractRawHref: extractRawHref,
  createUrlObject: createUrlObject,
  generateUrl: generateUrl
};
