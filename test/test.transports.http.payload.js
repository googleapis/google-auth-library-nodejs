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

var queryString = require('querystring');
var assert = require('assert');
var payload = require('../lib/transports/http/payload.js');

describe('HTTP wrapper utils -- payload utils', function () {
  describe('generateRequestPayload', function () {
    describe('options containing json prop only', function () {
      it('Should return a requestPayload prop with JSON data', function () {
        var GIVEN_OPTIONS = {
          json: true,
          form: {a: true, b: false}
        };
        var out = payload({}, GIVEN_OPTIONS);
        assert.deepEqual({
          requestPayload: {
            isJSON: true,
            payload: JSON.stringify(GIVEN_OPTIONS.form)
          }
        }, out);
      });
    });
    describe('options containing a form prop only', function () {
      it('Should return a requestPayload prop with FORM data', function () {
        var GIVEN_OPTIONS = {
          form: {a: false, b: true}
        };
        var out = payload({}, GIVEN_OPTIONS);
        assert.deepEqual({
          requestPayload: {
            isJSON: false,
            payload: queryString.stringify(GIVEN_OPTIONS.form)
          }
        }, out);
      });
    });
    describe('options containing a qs prop', function () {
      it('Should return a requestPayload prop with a queryString prop',
        function () {
          var GIVEN_OPTIONS = {qs: {a: true, b: false}};
          var out = payload({}, GIVEN_OPTIONS);
          assert.deepEqual({
            requestPayload: {
              queryString: queryString.stringify(GIVEN_OPTIONS.qs)
            }
          }, out);
        }
      );
    });
    describe('options containing no identifying payload props', function () {
      it('Should return an unmodified options object', function () {
        var GIVEN_OPTIONS = {url: 'https://www.xyz.com/get/'};
        var out = payload({}, GIVEN_OPTIONS);
        assert.deepEqual({}, out);
      });
    });
  });
});
