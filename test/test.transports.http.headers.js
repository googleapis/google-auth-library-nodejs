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

var assert = require('assert');
var merge = require('lodash.merge');
var headers = require('../lib/transports/http/headers.js');

describe('HTTP wrapper utils -- headers utils', function () {
  describe('generating headers', function () {
    var payload = '{"json": true}';
    var EXPECTED_GENERATED_CONTENT_HEADERS = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    };
    var GIVEN_OPTIONS = {
      method: 'PATCH',
      headers: {
        'Metadata-Flavor': 'spicy'
      }
    };
    var GENERATED_OPTIONS = {
      requestPayload: {
        isJSON: true,
        payload: payload
      }
    };
    var out = headers(GENERATED_OPTIONS, GIVEN_OPTIONS);
    it('Should set hasBody to true', function () {
      assert.strictEqual(out.hasBody, true);
    });
    it('Should generate a requestOptions object', function () { 
      assert.deepEqual(
        merge(
          {
            requestOptions: {
              method: GIVEN_OPTIONS.method,
              headers: GIVEN_OPTIONS.headers
            }
          },
          {requestOptions: {headers: {'User-Agent': headers.USER_AGENT()}}},
          {requestOptions: {headers: EXPECTED_GENERATED_CONTENT_HEADERS}}
        ).requestOptions,
        out.requestOptions
      );
    });
  });
});
