/**
 * Copyright 2017 Google Inc. All Rights Reserved.
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
var AuthClient = require('../lib/auth/authclient.js');
var nock = require('nock');

nock.disableNetConnect();

describe('AuthClient', function () {
  var eut;
  beforeEach(function () {
    eut = new AuthClient();
  });
  describe('Class behaviour', function () {
    it('Should have a request function property which is abstract', function () {
      assert.throws(eut.request);
    });
    it('Should have setCredentials function property which sets a property on the instance',
      function () {
        var CREDS = 'xyz';
        assert.strictEqual(eut.credentials, undefined);
        eut.setCredentials(CREDS);
        assert.strictEqual(eut.credentials, CREDS);
      }
    );
  });
});
