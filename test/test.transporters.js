/**
 * Copyright 2013 Google Inc. All Rights Reserved.
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
var DefaultTransporter = require('../lib/transporters');
var nock = require('nock');
var version = require('../package.json').version;

nock.disableNetConnect();

describe('Transporters', function() {

  var defaultUserAgentRE = 'google-api-nodejs-client/\\d+.\\d+.\\d+';
  var transporter = new DefaultTransporter();

  it('should set default client user agent if none is set', function() {
    var opts = transporter.configure({});
    var re = new RegExp(defaultUserAgentRE);
    assert(re.test(opts.headers['User-Agent']));
  });

  it('should append default client user agent to the existing user agent', function() {
    var applicationName = 'MyTestApplication-1.0';
    var opts = transporter.configure({
      headers: { 'User-Agent': applicationName }
    });
    var re = new RegExp(applicationName + ' ' + defaultUserAgentRE);
    assert(re.test(opts.headers['User-Agent']));
  });

  it('should not append default client user agent to the existing user ' +
      'agent more than once', function() {
    var applicationName = 'MyTestApplication-1.0 google-api-nodejs-client/' + version;
    var opts = transporter.configure({
      headers: { 'User-Agent': applicationName }
    });
    assert.equal(opts.headers['User-Agent'], applicationName);
  });

  it('should create a single error from multiple response errors', function(done) {
    var firstError = {
      message: 'Error 1'
    };
    var secondError = {
      message: 'Error 2'
    };
    nock('http://example.com')
      .get('/api')
      .reply(400, {
        error: {
          code: 500,
          errors: [ firstError, secondError ]
        }
      });

    transporter.request({
      uri: 'http://example.com/api',
    }, function(error) {
      assert(error.message === 'Error 1\nError 2');
      assert(error.code, 500);
      assert(error.errors.length, 2);
      done();
    });
  });
});
