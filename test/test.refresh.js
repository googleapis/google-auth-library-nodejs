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
var googleAuth = require('../lib/auth/googleauth.js');
var nock = require('nock');
var fs = require('fs');

nock.disableNetConnect();

// Creates a standard JSON credentials object for testing.
function createJSON() {
  return {
    'client_secret': 'privatekey',
    'client_id': 'client123',
    'refresh_token': 'refreshtoken',
    'type': 'authorized_user'
  };
}

describe('Refresh Token auth client', function() {

});

describe('.fromJson', function () {

  it('should error on null json', function () {
    var auth = new googleAuth();
    var jwt = new auth.JWT();
    jwt.fromJSON(null, function (err) {
      assert.equal(true, err instanceof Error);
    });
  });

  it('should error on empty json', function () {
    var auth = new googleAuth();
    var jwt = new auth.JWT();
    jwt.fromJSON({}, function (err) {
      assert.equal(true, err instanceof Error);
    });
  });

  it('should error on missing client_id', function () {
    var json = createJSON();
    delete json.client_id;

    var auth = new googleAuth();
    var jwt = new auth.JWT();
    jwt.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
    });
  });

  it('should error on missing client_secret', function () {
    var json = createJSON();
    delete json.client_secret;

    var auth = new googleAuth();
    var jwt = new auth.JWT();
    jwt.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
    });
  });

  it('should error on missing refresh_token', function () {
    var json = createJSON();
    delete json.refresh_token;

    var auth = new googleAuth();
    var jwt = new auth.JWT();
    jwt.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
    });
  });
});
