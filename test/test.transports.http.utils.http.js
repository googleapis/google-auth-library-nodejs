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
var noOp = require('lodash.noop');
var utils = require('../lib/transports/http/utils/http.js');
var semver = require('semver');

describe('HTTP/HTTPS utils API', function () {
  describe('generateErrorInformation', function () {
    var generateErrorInformation = utils.generateErrorInformation;
    describe('Injecting error info with an errored body', function () {
      describe('A singular error', function () {
        describe('With body.error as type string', function () {
          var BODY = {error: 'test_0'};
          var RESPONSE = {statusCode: 500};
          var err = generateErrorInformation(BODY, RESPONSE);
          it('Should return an error', function () {
            assert(err instanceof Error);
          });
          it('Should have the message content of the body', function () {
            assert.strictEqual(err.message, BODY.error);
          });
          it(
            'Should have a code property which should be the resps statusCode',
            function () {
              assert.strictEqual(err.code, RESPONSE.statusCode);
            }
          );
        });
        describe('With body.error.message as type string', function () {
          var BODY = {error: {message: 'test_2'}};
          var RESPONSE = {statusCode: 502};
          var err = generateErrorInformation(BODY, RESPONSE);
          it('Should return an error', function () {
            assert(err instanceof Error);
          });
          it('Should have the message content of the error.message prop',
            function () {
              assert.strictEqual(err.message, BODY.error.message);
            }
          );
          it(
            'Should have a code property which should be the body statusCode',
            function () {
              assert.strictEqual(err.code, RESPONSE.statusCode);
            }
          );
        });
        describe(
          'With body.error.message as type string and body.error.code set',
          function () {
            var BODY = {error: {message: 'test_2', code: 501}};
            var RESPONSE = {statusCode: 500};
            var err = generateErrorInformation(BODY, RESPONSE);
            it('Should return an error', function () {
              assert(err instanceof Error);
            });
            it('Should have the message content of the error.message prop',
              function () {
                assert.strictEqual(err.message, BODY.error.message);
              }
            );
            it(
              'Should have a code property which should be the body statusCode',
              function () {
                assert.strictEqual(err.code, BODY.error.code);
              }
            );
          }
        );
      });
      describe('Multiple errors', function () {
        var errors = [{message: 'msg 1'}, {message: 'msg 2'}];
        var BODY = {error: {errors: errors}, code: 404};
        var RESPONSE = {statusCode: 400};
        var err = generateErrorInformation(BODY, RESPONSE);
        it('Should return an error', function () {
          assert(err instanceof Error);
        });
        it('Should have the error messages combined on the message prop',
          function () {
            assert.strictEqual(BODY.error.errors.map(function (err) {
              return err.message;
            }).join('\n'), err.message);
          }
        );
        it('Should have a errors property containing the array of errors',
          function () {
            assert.deepEqual(err.errors, errors);
          }
        );
        it('Should have a code property which should be the error.code prop',
          function () {
            assert.strictEqual(BODY.error.code, err.code);
          }
        );
      });
    });
    describe('Injecting error info without an errored body', function () {
      describe('response.statusCode is >= 500', function () {
        var BODY = 'SOME STRING';
        var RESPONSE = {statusCode: 500};
        var err = generateErrorInformation(BODY, RESPONSE);
        it('Should return an error', function () {
          assert(err instanceof Error);
        });
        it('Should have a message prop valued as BODY', function () {
          assert.strictEqual(err.message, BODY);
        });
        it('Should have a code prop value as RESPONSE.statusCode', function () {
          assert.strictEqual(err.code, RESPONSE.statusCode);
        });
      });
    });
    describe('Omitting injection due to non-errored body', function () {
      var BODY = 'SOME STRING AGAIN';
      var RESPONSE = {statusCode: 200};
      var err = generateErrorInformation(BODY, RESPONSE);
      it('Should return null', function () {
        assert.strictEqual(err, null);
      });
    });
  });
  describe('wrapGivenCallback', function () {
    var wrapGivenCallback = utils.wrapGivenCallback;
    describe('Not given a function to wrap', function () {
      it('Should return a noOp function', function () {
        var out = wrapGivenCallback(null);
        assert.strictEqual(out, noOp);
      });
    });
    describe('Testing the closure produced', function () {
      describe('Error behaviour', function () {
        describe('If err argument is given', function () {
          it('Should error-back', function (done) {
            var MSG = 'test message';
            var ERROR = new Error(MSG);
            var RESPONSE = {};
            var BODY = {};
            var fn = wrapGivenCallback(function (err, body, res) {
              assert(err instanceof Error);
              assert.strictEqual(err.message, MSG);
              assert.deepEqual(body, BODY);
              assert.deepEqual(res, RESPONSE);
              done();
            });
            fn(ERROR, RESPONSE, BODY);
          });
        });
        describe('If body argument is omitted', function () {
          it('Should error-back', function (done) {
            var ERROR = null;
            var RESPONSE = {};
            var BODY = null;
            var fn = wrapGivenCallback(function (err, body, res) {
              assert.strictEqual(err, ERROR);
              assert.strictEqual(body, BODY);
              assert.deepEqual(res, RESPONSE);
              done();
            });
            fn(ERROR, RESPONSE, BODY);
          });
        });
        describe('If body has error information', function () {
          it('Should error-back', function (done) {
            var ERROR = null;
            var RESPONSE = {statusCode: 500};
            var BODY = {error: 'INTERNAL SERVER ERROR'};
            var fn = wrapGivenCallback(function(err, body, res) {
              assert(err instanceof Error);
              assert.strictEqual(err.message, BODY.error);
              assert.strictEqual(err.code, RESPONSE.statusCode);
              assert.strictEqual(body, null);
              assert.deepEqual(res, RESPONSE);
              done();
            });
            fn(ERROR, RESPONSE, BODY);
          });
        });
      });
      describe('Success behaviour', function () {
        describe('Response body handling', function () {
          describe('JSON is the content of body', function () {
            describe('Valid JSON', function () {
              it('Should parse the JSON into an object', function (done) {
                var ERROR = null;
                var RESPONSE = {statusCode: 200};
                var BODY = JSON.stringify({test: true});
                var fn = wrapGivenCallback(function (err, body, res) {
                  assert.strictEqual(err, null);
                  assert.deepEqual(body, JSON.parse(BODY));
                  assert.deepEqual(res, RESPONSE);
                  done();
                });
                fn(ERROR, RESPONSE, BODY);
              });
            });
            describe('Malformed JSON', function () {
              it('Should leave the string as a string', function (done) {
                var ERROR = null;
                var RESPONSE = {statusCode: 200};
                var BODY = '{"test": true'; // MISSING ENDING CURLY-BRACE
                var fn = wrapGivenCallback(function (err, body, res) {
                  assert.strictEqual(err, null);
                  assert.deepEqual(body, BODY);
                  assert.deepEqual(res, RESPONSE);
                  done();
                });
                fn(ERROR, RESPONSE, BODY);
              });
            });
          });
          describe('A regular string is the content of the body', function () {
            it('Should pass the value of the string through', function (done) {
              var ERROR = null;
              var RESPONSE = {statusCode: 200};
              var BODY = 'THIS IS A STRING';
              var fn = wrapGivenCallback(function (err, body, res) {
                assert.strictEqual(err, null);
                assert.strictEqual(body, BODY);
                assert.deepEqual(res, RESPONSE);
                done();
              });
              fn(ERROR, RESPONSE, BODY);
            });
          });
        });
      });
    });
  });
  describe('getTransport', function () {
    var getTransport = utils.getTransport;
    describe('If given true', function () {
      it('Should return the https module', function () {
        if (!semver.satisfies(process.version, '>1.6')) {
          // globalAgent.protocol is not available on 0.10.x
          this.skip();
          assert.strictEqual(getTransport(true).globalAgent.protocol, 'https:');
        }
      });
    });
    describe('If given false', function () {
      it('Should return the http module', function () {
        if (!semver.satisfies(process.version, '>1.6')) {
          // globalAgent.protocol is not available on 0.10.x
          this.skip();
          assert.strictEqual(getTransport(false).globalAgent.protocol, 'http:');
        }
      });
    });
  });
});
