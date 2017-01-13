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
  describe('extractFormData', function () {
    it('Should stringify a valid object', function () {
      var DATA = {test: true, test2: 12, test3: 'test'};
      var qs = payload.extractFormData(DATA);
      assert(qs.indexOf('test=true') > -1);
      assert(qs.indexOf('test2=12') > -1);
      assert(qs.indexOf('test3=test') > -1);
    });
    it('Should not throw given an non-object', function () {
      var DATA = null;
      var qs = payload.extractFormData(DATA);
      assert.strictEqual(qs, '');
    });
  });
  describe('extractJsonData', function () {
    describe('Invoked with no arguments', function () {
      it('Should return an empty string', function () {
        assert.strictEqual(payload.extractJsonData(), '');
      });
    });
    describe('Given a string as the first arg', function () {
      it('Should return the string', function () {
        var str = 'test';
        var out = payload.extractJsonData(str);
        assert.strictEqual(str, out);
      });
    });
    describe('Given a object as the first arg', function () {
      it('Should attempt to stringify the provided object', function () {
        var obj = {test: true};
        var out = payload.extractJsonData(obj);
        assert.strictEqual(JSON.stringify(obj), out);
      });
    });
    describe('Given the boolean "true" as the first argument', function () {
      describe('Given an object as the second argument', function () {
        it('Should return a stringified version of the second argument',
          function () {
            var obj = {test: true};
            var out = payload.extractJsonData(true, obj);
            assert.strictEqual(JSON.stringify(obj), out);
          }
        );
      });
      describe(
        'Given an object as the third argument and a non-object as the second',
        function () {
          it('Should return a stringified version of the third argument',
            function () {
              var obj = {test2: true};
              var out = payload.extractJsonData(true, null, obj);
              assert.strictEqual(JSON.stringify(obj), out);
            }
          );
        }
      );
      describe('Given no usable payloads as arguments to invocation', function () {
        it('Should return an empty string', function () {
          assert.strictEqual(payload.extractJsonData(true), '');
        });
      });
    });
  });
  describe('generateRequestPayload', function () {
    describe('options containing json prop only', function () {
      it('Should return a requestPayload prop with JSON data', function () {
        var GIVEN_OPTIONS = {
          json: true,
          form: {a: true, b: false}
        };
        var out = payload.generateRequestPayload({}, GIVEN_OPTIONS);
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
        var out = payload.generateRequestPayload({}, GIVEN_OPTIONS);
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
          var out = payload.generateRequestPayload({}, GIVEN_OPTIONS);
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
        var out = payload.generateRequestPayload({}, GIVEN_OPTIONS);
        assert.deepEqual({}, out);
      });
    });
  });
});
