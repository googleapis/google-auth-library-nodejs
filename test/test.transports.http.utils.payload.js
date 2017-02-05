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
var utils = require('../lib/transports/http/utils/payload.js');

describe('HTTP/HTTPS utils API', function () {
  describe('extractJsonData', function () {
    var extractJsonData = utils.extractJsonData;
    describe('Invoked with no arguments', function () {
      it('Should return an empty string', function () {
        assert.strictEqual(extractJsonData(), '');
      });
    });
    describe('Given a string as the first arg', function () {
      it('Should return the string', function () {
        var str = 'test';
        var out = extractJsonData(str);
        assert.strictEqual(str, out);
      });
    });
    describe('Given a object as the first arg', function () {
      it('Should attempt to stringify the provided object', function () {
        var obj = {test: true};
        var out = extractJsonData(obj);
        assert.strictEqual(JSON.stringify(obj), out);
      });
    });
    describe('Given the boolean "true" as the first argument', function () {
      describe('Given an object as the second argument', function () {
        it('Should return a stringified version of the second argument',
          function () {
            var obj = {test: true};
            var out = extractJsonData(true, obj);
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
              var out = extractJsonData(true, null, obj);
              assert.strictEqual(JSON.stringify(obj), out);
            }
          );
        }
      );
      describe('Given no usable payloads as arguments to invocation', function () {
        it('Should return an empty string', function () {
          assert.strictEqual(extractJsonData(true), '');
        });
      });
    });
  });
});
