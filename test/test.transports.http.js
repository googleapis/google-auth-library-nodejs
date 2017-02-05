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
var http = require('../lib/transports/http.js');
var nock = require('nock');

describe('HTTP/HTTPS transport API', function () {
  before(function () {
    nock.disableNetConnect();
  });
  after(function () {
    nock.enableNetConnect();
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
