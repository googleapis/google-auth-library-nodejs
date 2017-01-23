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
var noOp = require('lodash.noop');
var url = require('url');
var headers = require('../lib/transports/http/headers.js');
var http = require('../lib/transports/http.js');
var nock = require('nock');
var semver = require('semver');

describe('HTTP/HTTPS transport API', function () {
  before(function () {
    nock.disableNetConnect();
  });
  after(function () {
    nock.enableNetConnect();
  });
  describe('normalizeRequestOptions', function () {
    var normalizeRequestOptions = http.normalizeRequestOptions;
    describe('Given a valid options object', function () {
      var OPTIONS = {
        url: 'https://www.google.com/stub/path?qs=true',
        method: 'PATCH',
        json: {test: true},
        headers: {
          'Metadata-Taste': 'umami'
        }
      };
      var EXPECTED_GENERATED_CONTENT_HEADERS = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(JSON.stringify(OPTIONS.json))
      };
      var out = normalizeRequestOptions(OPTIONS);
      var urlObj = url.parse(OPTIONS.url);
      it('Should return a http compatible request object', function () {    
        assert.deepEqual(out, merge({}, {
          hasBody: true,
          urlObject: urlObj,
          href: OPTIONS.url,
          isUsingHttps: true,
          requestOptions: {
            host: urlObj.host,
            path: urlObj.path,
            method: OPTIONS.method,
            headers: merge({}, OPTIONS.headers,
              {'User-Agent': headers.USER_AGENT},
              EXPECTED_GENERATED_CONTENT_HEADERS)
          },
          requestPayload: {
            isJSON: true,
            payload: JSON.stringify(OPTIONS.json)
          }
        }));
      });
    });
  });
  describe('generateErrorInformation', function () {
    var generateErrorInformation = http.generateErrorInformation;
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
    var wrapGivenCallback = http.wrapGivenCallback;
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
    var getTransport = http.getTransport;
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
  describe('Request lifecycle mocking (request & formulateRequest)', function () {
    var request = http.request;
    var HOST = 'https://www.example.org';
    var PATHS = {
      GET: '/get/path',
      POST: '/post/path'
    };
    var QS = {test: true, secondParam: 1234};
    var RESP_BODY = 'DONE';
    afterEach(function () {nock.cleanAll();});
    describe('GET requests', function () {
      describe('Without querystring parameters', function () {
        it('Should succeed with valid parameters', function (done) {
          var scope = nock(HOST).get(PATHS.GET).once().reply(200, RESP_BODY);
          request({url: HOST+PATHS.GET}, function (err, body, resp) {
            assert.strictEqual(err, null);
            assert.strictEqual(body, RESP_BODY);
            assert.strictEqual(resp.statusCode, 200);
            scope.done();
            done();
          });
        });
        it('Should provide error information given failure', function (done) {
          var scope = nock(HOST).get(PATHS.GET).once().reply(500, RESP_BODY);
          request({url: HOST+PATHS.GET}, function (err, body, resp) {
            assert(err instanceof Error);
            assert.strictEqual(err.message, RESP_BODY);
            assert.strictEqual(resp.statusCode, 500);
            scope.done();
            done();
          });
        });
      });
      describe('With querystring parameters', function () {
        it('Should succeed with valid parameters', function (done) {
          var scope = nock(HOST).get(PATHS.GET).once().query(QS)
            .reply(200, RESP_BODY);
          request({url: HOST+PATHS.GET, qs: QS},
            function (err, body, resp) {
              assert.strictEqual(err, null);
              assert.strictEqual(body, RESP_BODY);
              assert.strictEqual(resp.statusCode, 200);
              scope.done();
              done();
            }
          );
        });
      });
    });
    describe('POST requests', function () {
      var METHOD = 'POST';
      describe('With JSON request/reply payloads', function () {
        var RESP_BODY = {testIt: 'DONE'};
        var POST_BODY = {testMe: true};
        it('Should reply with the success body', function (done) {
          var scope = nock(HOST).post(PATHS.POST, POST_BODY).once()
            .reply(200, RESP_BODY);
          request({url: HOST+PATHS.POST, json: POST_BODY, method: METHOD},
            function (err, body, resp) {
              assert.strictEqual(err, null);
              assert.deepEqual(body, RESP_BODY);
              assert.strictEqual(resp.statusCode, 200);
              scope.done();
              done();
            }
          );
        });
        it('Should provide error information given failure', function (done) {
          var ERROR_MSG = 'A ERROR MESSAGE';
          var scope = nock(HOST).post(PATHS.POST, POST_BODY).once()
            .replyWithError(ERROR_MSG);
          request(
            {uri: HOST+PATHS.POST, json: true, body: POST_BODY, method: METHOD},
            function (err, body, resp) {
              assert(err instanceof Error);
              assert.strictEqual(err.message, ERROR_MSG);
              assert.strictEqual(resp, null);
              assert.strictEqual(body, null);
              scope.done();
              done();
            }
          );
        });
      });
    });
  });
});
