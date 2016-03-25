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
var fs = require('fs');
var googleAuth = require('../lib/auth/googleauth.js');
var jws = require('jws');
var keypair = require('keypair');
var nock = require('nock');

nock.disableNetConnect();

// Creates a standard JSON credentials object for testing.
function createJSON() {
  return {
    'private_key_id': 'key123',
    'private_key': 'privatekey',
    'client_email': 'hello@youarecool.com',
    'client_id': 'client123',
    'type': 'service_account'
  };
}

describe('Initial credentials', function() {

  it('should create a dummy refresh token string', function () {
    // It is important that the compute client is created with a refresh token value filled
    // in, or else the rest of the logic will not work.
    var auth = new googleAuth();
    var jwt = new auth.JWT();
    assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
  });

});

describe('JWT auth client', function() {

  describe('.authorize', function() {

    it('should get an initial access token', function(done) {
      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');
      jwt.gToken = function(opts) {
        assert.equal('foo@serviceaccount.com', opts.iss);
        assert.equal('/path/to/key.pem', opts.keyFile);
        assert.deepEqual(['http://bar', 'http://foo'], opts.scope);
        assert.equal('bar@subjectaccount.com', opts.sub);
        return {
          key: 'private-key-data',
          iss: 'foo@subjectaccount.com',
          getToken: function(opt_callback) {
            return opt_callback(null, 'initial-access-token');
          }
        };
      };
      jwt.authorize(function() {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
        assert.equal('private-key-data', jwt.key);
        assert.equal('foo@subjectaccount.com', jwt.email);
        done();
      });
    });

    it('should accept scope as string', function(done) {
      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          'http://foo',
          'bar@subjectaccount.com');

      jwt.gToken = function(opts) {
        assert.equal('http://foo', opts.scope);
        done();
        return {
          getToken: function() {}
        };
      };

      jwt.authorize();
    });

  });

  describe('.getAccessToken', function() {

    describe('when scopes are set', function() {

      it('can get obtain new access token', function(done) {
        var auth = new googleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            '/path/to/key.pem',
            null,
            ['http://bar', 'http://foo'],
            'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var want = 'abc123';
        jwt.gtoken = {
          getToken: function(callback) {
            return callback(null, want);
          }
        };

        jwt.getAccessToken(function(err, got) {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.strictEqual(want, got, 'the access token was wrong: ' + got);
          done();
        });
      });

    });

  });

  describe('.getRequestMetadata', function() {

    describe('when scopes are set', function() {

      it('can obtain new access token', function(done) {
        var auth = new googleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            '/path/to/key.pem',
            null,
            ['http://bar', 'http://foo'],
            'bar@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var wanted_token = 'abc123';
        jwt.gtoken = {
          getToken: function(callback) {
            return callback(null, wanted_token);
          }
        };
        var want = 'Bearer ' + wanted_token;
        var retValue = 'dummy';
        var unusedUri = null;
        var res = jwt.getRequestMetadata(unusedUri, function(err, got) {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.strictEqual(want, got.Authorization,
                             'the authorization header was wrong: ' + got.Authorization);
          done();
          return retValue;
        });
        assert.strictEqual(res, retValue);
      });

    });

    describe('when scopes are not set, but a uri is provided', function() {

      it('gets a jwt header access token', function(done) {
        var keys = keypair(1024 /* bitsize of private key */);
        var email = 'foo@serviceaccount.com';
        var auth = new googleAuth();
        var jwt = new auth.JWT(
            'foo@serviceaccount.com',
            null,
            keys['private'],
            null,
            'ignored@subjectaccount.com');

        jwt.credentials = {
          refresh_token: 'jwt-placeholder'
        };

        var testUri = 'http:/example.com/my_test_service';
        var retValue = 'dummy';
        var res = jwt.getRequestMetadata(testUri, function(err, got) {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.notStrictEqual(null, got, 'the creds should be present');
          var decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
          assert.strictEqual(email, decoded.payload.iss);
          assert.strictEqual(email, decoded.payload.sub);
          assert.strictEqual(testUri, decoded.payload.aud);
          done();
          return retValue;
        });
        assert.strictEqual(res, retValue);
      });

    });

  });

  describe('.request', function() {

    it('should refresh token if missing access token', function(done) {
      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        refresh_token: 'jwt-placeholder'
      };

      jwt.gtoken = {
        getToken: function(callback) {
          callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://bar' }, function() {
        assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if expired', function(done) {
      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() - 1000
      };

      jwt.gtoken = {
        getToken: function(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://bar' }, function() {
        assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if the server returns 403', function(done) {
      var scope = nock('http://example.com')
          .log(console.log)
          .get('/access')
          .reply(403);

      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://example.com'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() + 5000
      };

      jwt.gtoken = {
        getToken: function(callback) {
          return callback(null, 'abc123');
        }
      };

      jwt.request({ uri : 'http://example.com/access' }, function() {
        assert.equal('abc123', jwt.credentials.access_token);
        nock.cleanAll();
        done();
      });
    });

    it('should not refresh if not expired', function(done) {
      var scope = nock('https://accounts.google.com')
          .log(console.log)
          .post('/o/oauth2/token', '*')
          .reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() + 5000
      };

      jwt.request({ uri : 'http://bar' }, function() {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal(false, scope.isDone());
        nock.cleanAll();
        done();
      });
    });

    it('should assume access token is not expired', function(done) {
      var scope = nock('https://accounts.google.com')
          .log(console.log)
          .post('/o/oauth2/token', '*')
          .reply(200, { access_token: 'abc123', expires_in: 10000 });

      var auth = new googleAuth();
      var jwt = new auth.JWT(
          'foo@serviceaccount.com',
          '/path/to/key.pem',
          null,
          ['http://bar', 'http://foo'],
          'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'jwt-placeholder'
      };

      jwt.request({ uri : 'http://bar' }, function() {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal(false, scope.isDone());
        nock.cleanAll();
        done();
      });
    });

  });

  it('should return expiry_date in milliseconds', function(done) {
    var auth = new googleAuth();
    var jwt = new auth.JWT(
        'foo@serviceaccount.com',
        '/path/to/key.pem',
        null,
        ['http://bar', 'http://foo'],
        'bar@subjectaccount.com');

    jwt.credentials = {
      refresh_token: 'jwt-placeholder'
    };

    var dateInMillis = (new Date()).getTime();

    jwt.gtoken = {
      getToken: function(callback) {
        return callback(null, 'token');
      },
      expires_at: dateInMillis
    };

    jwt.refreshToken_({ uri : 'http://bar' }, function(err, creds) {
      assert.equal(dateInMillis, creds.expiry_date);
      done();
    });
  });

});

describe('.createScoped', function() {
  // set up the auth module.
  var auth;
  beforeEach(function() {
    auth = new googleAuth();
  });

  it('should clone stuff', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('x');

    assert.equal(jwt.email, clone.email);
    assert.equal(jwt.keyFile, clone.keyFile);
    assert.equal(jwt.key, clone.key);
    assert.equal(jwt.subject, clone.subject);
  });

  it('should handle string scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('newscope');
    assert.equal('newscope', clone.scopes);
  });

  it('should handle array scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped(['gorilla', 'chimpanzee', 'orangutan']);
    assert.equal(3, clone.scopes.length);
    assert.equal('gorilla', clone.scopes[0]);
    assert.equal('chimpanzee', clone.scopes[1]);
    assert.equal('orangutan', clone.scopes[2]);
  });

  it('should handle null scope', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped();
    assert.equal(null, clone.scopes);
  });

  it('should set scope when scope was null', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      null,
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    assert.equal('hi', clone.scopes);
  });

  it('should handle nulls', function() {
    var jwt = new auth.JWT();

    var clone = jwt.createScoped('hi');
    assert.equal(jwt.email, null);
    assert.equal(jwt.keyFile, null);
    assert.equal(jwt.key, null);
    assert.equal(jwt.subject, null);
    assert.equal('hi', clone.scopes);
  });

  it('should not return the original instance', function() {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    var clone = jwt.createScoped('hi');
    assert.notEqual(jwt, clone);
  });

});

describe('.createScopedRequired', function() {
  // set up the auth module.
  var auth;
  beforeEach(function() {
    auth = new googleAuth();
  });

  it('should return true when scopes is null', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      null,
      'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty array', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      [],
      'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty string', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      '',
      'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in string', function () {
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      'http://foo',
      'bar@subjectaccount.com');

    assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in array', function () {
    var auth = new googleAuth();
    var jwt = new auth.JWT(
      'foo@serviceaccount.com',
      '/path/to/key.pem',
      null,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com');

    assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is not an array or a string, but can be used as a string',
    function () {

      var auth = new googleAuth();
      var jwt = new auth.JWT(
        'foo@serviceaccount.com',
        '/path/to/key.pem',
        null,
        2,
        'bar@subjectaccount.com');

      assert.equal(false, jwt.createScopedRequired());
    });
});

describe('.fromJson', function () {
  // set up the test json and the jwt instance being tested.
  var jwt, json;
  beforeEach(function() {
    json = createJSON();
    var auth = new googleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null json', function (done) {
    jwt.fromJSON(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', function (done) {
    jwt.fromJSON({}, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', function (done) {
    delete json.client_email;

    jwt.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', function (done) {
    delete json.private_key;

    jwt.fromJSON(json, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', function (done) {
    jwt.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(json.client_email, jwt.email);
      done();
    });
  });

  it('should create JWT with private_key', function (done) {
    jwt.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(json.private_key, jwt.key);
      done();
    });
  });

  it('should create JWT with null scopes', function (done) {
    jwt.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(null, jwt.scopes);
      done();
    });
  });

  it('should create JWT with null subject', function (done) {
    jwt.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(null, jwt.subject);
      done();
    });
  });

  it('should create JWT with null keyFile', function (done) {
    jwt.fromJSON(json, function (err) {
      assert.equal(null, err);
      assert.equal(null, jwt.keyFile);
      done();
    });
  });

});

describe('.fromStream', function () {
  // set up the jwt instance being tested.
  var jwt;
  beforeEach(function() {
    var auth = new googleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null stream', function (done) {
    jwt.fromStream(null, function (err) {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a jwt', function (done) {
    // Read the contents of the file into a json object.
    var fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
    var json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    var stream = fs.createReadStream('./test/fixtures/private.json');

    // And pass it into the fromStream method.
    jwt.fromStream(stream, function (err) {
      assert.equal(null, err);

      // Ensure that the correct bits were pulled from the stream.
      assert.equal(json.private_key, jwt.key);
      assert.equal(json.client_email, jwt.email);
      assert.equal(null, jwt.keyFile);
      assert.equal(null, jwt.subject);
      assert.equal(null, jwt.scope);

      done();
    });
  });

});
