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

var parseUrl = require('url').parse;
var assert = require('assert');
var url = require('../lib/transports/http/url.js');


describe('HTTP wrapper utils -- url utils', function () {
  describe('generateUrl', function () {
    describe('Given a valid set of generated and given options', function () {
      var GENERATED_OPTIONS = {};
      var GIVEN_OPTIONS = {url: 'https://abc.org/a/get/path?with=queryString'};
      var PARSED_URL = parseUrl(GIVEN_OPTIONS.url);
      it('Should return a populated options object', function () {
        assert.deepEqual(
          url(GENERATED_OPTIONS, GIVEN_OPTIONS),
          {
            isUsingHttps: true,
            href: GIVEN_OPTIONS.url,
            urlObject: PARSED_URL,
            requestOptions: {
              host: PARSED_URL.host,
              path: PARSED_URL.path
            }
          }
        );
      });
    });
  });
});
