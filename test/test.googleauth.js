/**
 * Copyright 2014 Google Inc. All Rights Reserved.
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
var GoogleAuth = require('../lib/auth/googleauth.js');
var nock = require('nock');
var fs = require('fs');

nock.disableNetConnect();

// Creates a standard JSON auth object for testing.
function createJwtJSON() {
  return {
    'private_key_id': 'key123',
    'private_key': 'privatekey',
    'client_email': 'hello@youarecool.com',
    'client_id': 'client123',
    'type': 'service_account'
  };
}

function createRefreshJSON() {
  return {
    'client_secret': 'privatekey',
    'client_id': 'client123',
    'refresh_token': 'refreshtoken',
    'type': 'authorized_user'
  };
}

// Matches the ending of a string.
function stringEndsWith(str, suffix) {
  return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

// Simulates a path join.
function pathJoin(item1, item2) {
  return item1 + ':' + item2;
}

// Returns the value.
function returns(value) {
  return function() {
    return value;
  };
}

function callsBack(value) {
  return function(callback) {
    callback(value);
  };
}

// Blocks the GOOGLE_APPLICATION_CREDENTIALS by default. This is necessary in case it is actually
// set on the host machine executing the test.
function blockGoogleApplicationCredentialEnvironmentVariable(auth) {
  return insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS', null);
}

// Intercepts the specified environment variable, returning the specified value.
function insertEnvironmentVariableIntoAuth(
  auth, environmentVariableName, environmentVariableValue) {
  var originalGetEnvironmentVariableFunction = auth._getEnv;

  auth._getEnv = function(name) {
    if (name === environmentVariableName) {
      return environmentVariableValue;
    }

    return originalGetEnvironmentVariableFunction(name);
  };
}

// Intercepts the specified file path and inserts the mock file path.
function insertWellKnownFilePathIntoAuth(auth, filePath, mockFilePath) {
  var originalMockWellKnownFilePathFunction = auth._mockWellKnownFilePath;

  auth._mockWellKnownFilePath = function(path) {
    if (path === filePath) {
      return mockFilePath;
    }

    return originalMockWellKnownFilePathFunction(filePath);
  };
}

// Nothing.
function noop() { }

// Executes the doneCallback after the nTH call.
function doneWhen(doneCallback, count) {
  var i = 0;

  return function() {
    ++i;

    if (i === count) {
      doneCallback();
    } else if (i > count) {
      throw new Error('Called too many times. Test error?');
    }
  };
}

describe('GoogleAuth', function() {
  describe('.fromJson', function () {

    it('should error on null json', function (done) {
      var auth = new GoogleAuth();
      auth.fromJSON(null, function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    describe('JWT token', function() {

      it('should error on empty json', function (done) {
        var auth = new GoogleAuth();
        auth.fromJSON({}, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_email', function (done) {
        var json = createJwtJSON();
        delete json.client_email;

        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing private_key', function (done) {
        var json = createJwtJSON();
        delete json.private_key;

        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should create JWT with client_email', function (done) {
        var json = createJwtJSON();
        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err, result) {
          assert.equal(null, err);
          assert.equal(json.client_email, result.email);
          done();
        });
      });

      it('should create JWT with private_key', function (done) {
        var json = createJwtJSON();
        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err, result) {
          assert.equal(null, err);
          assert.equal(json.private_key, result.key);
          done();
        });
      });

      it('should create JWT with null scopes', function (done) {
        var json = createJwtJSON();
        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err, result) {
          assert.equal(null, err);
          assert.equal(null, result.scopes);
          done();
        });
      });

      it('should create JWT with null subject', function (done) {
        var json = createJwtJSON();
        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err, result) {
          assert.equal(null, err);
          assert.equal(null, result.subject);
          done();
        });
      });

      it('should create JWT with null keyFile', function (done) {
        var json = createJwtJSON();
        var auth = new GoogleAuth();
        auth.fromJSON(json, function (err, result) {
          assert.equal(null, err);
          assert.equal(null, result.keyFile);
          done();
        });
      });
    });
    describe('Refresh token', function() {
      it('should error on empty json', function (done) {
        var auth = new GoogleAuth();
        var jwt = new auth.JWT();
        jwt.fromJSON({}, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_id', function (done) {
        var json = createRefreshJSON();
        delete json.client_id;

        var auth = new GoogleAuth();
        var jwt = new auth.JWT();
        jwt.fromJSON(json, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_secret', function (done) {
        var json = createRefreshJSON();
        delete json.client_secret;

        var auth = new GoogleAuth();
        var jwt = new auth.JWT();
        jwt.fromJSON(json, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing refresh_token', function (done) {
        var json = createRefreshJSON();
        delete json.refresh_token;

        var auth = new GoogleAuth();
        var jwt = new auth.JWT();
        jwt.fromJSON(json, function (err) {
          assert.equal(true, err instanceof Error);
          done();
        });
      });
    });
  });

  describe('.fromStream', function () {

    it('should error on null stream', function (done) {
      var auth = new GoogleAuth();
      auth.fromStream(null, function (err) {
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
      var auth = new GoogleAuth();
      auth.fromStream(stream, function (err, result) {
        assert.equal(null, err);

        // Ensure that the correct bits were pulled from the stream.
        assert.equal(json.private_key, result.key);
        assert.equal(json.client_email, result.email);
        assert.equal(null, result.keyFile);
        assert.equal(null, result.subject);
        assert.equal(null, result.scope);

        done();
      });
    });

    it('should read another stream and create a UserRefreshClient', function(done) {
      // Read the contents of the file into a json object.
      var fileContents = fs.readFileSync('./test/fixtures/refresh.json', 'utf-8');
      var json = JSON.parse(fileContents);

      // Now open a stream on the same file.
      var stream = fs.createReadStream('./test/fixtures/refresh.json');

      // And pass it into the fromStream method.
      var auth = new GoogleAuth();
      auth.fromStream(stream, function (err, result) {
        assert.ifError(err);

        // Ensure that the correct bits were pulled from the stream.
        assert.equal(json.client_id, result.clientId_);
        assert.equal(json.client_secret, result.clientSecret_);
        assert.equal(json.refresh_token, result._refreshToken);

        done();
      });
    });
  });

  describe('._getApplicationCredentialsFromFilePath', function () {

    it('should not error on valid symlink', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/goodlink', function (err) {
        assert.equal(false, err instanceof Error);
        done();
      });
    });

    it('should error on invalid symlink', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/badlink', function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on valid link to invalid data', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/emptylink', function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on null file path', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(null, function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on empty file path', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('', function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on non-string file path', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(2, function (err) {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on invalid file path', function (done) {
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('./nonexistantfile.json',
        function (err) {

          assert.equal(true, err instanceof Error);
          done();
        });
    });

    it('should error on directory', function (done) {
      // Make sure that the following path actually does point to a directory.
      var directory = './test/fixtures';
      assert.equal(true, fs.lstatSync(directory).isDirectory());

      // Execute.
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(directory,
        function (err) {

          assert.equal(true, err instanceof Error);
          done();
        });
    });

    it('should handle errors thrown from createReadStream', function (done) {
      // Set up a mock to throw from the createReadStream method.
      var auth = new GoogleAuth();
      auth._createReadStream = function () {
        throw new Error('Hans and Chewbacca');
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/private.json', function (err) {

        assert.equal(true, stringEndsWith(err.message, 'Hans and Chewbacca'));
        done();
      });
    });

    it('should handle errors thrown from fromStream', function (done) {
      // Set up a mock to throw from the fromStream method.
      var auth = new GoogleAuth();
      auth.fromStream = function () {
        throw new Error('Darth Maul');
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/private.json', function (err) {

        assert.equal(true, stringEndsWith(err.message, 'Darth Maul'));
        done();
      });
    });

    it('should handle errors passed from fromStream', function (done) {
      // Set up a mock to return an error from the fromStream method.
      var auth = new GoogleAuth();
      auth.fromStream = function (stream, callback) {
        callback(new Error('Princess Leia'));
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/private.json', function (err) {

        assert.equal(true, stringEndsWith(err.message, 'Princess Leia'));
        done();
      });
    });

    it('should correctly read the file and create a valid JWT', function (done) {
      // Read the contents of the file into a json object.
      var fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      var json = JSON.parse(fileContents);

      // Now pass the same path to the auth loader.
      var auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('./test/fixtures/private.json',
        function (err, result) {

          assert.equal(null, err);
          assert.equal(json.private_key, result.key);
          assert.equal(json.client_email, result.email);
          assert.equal(null, result.keyFile);
          assert.equal(null, result.subject);
          assert.equal(null, result.scope);
          done();
        });
    });
  });

  describe('._tryGetApplicationCredentialsFromEnvironmentVariable', function () {

    it('should return false when env var is not set', function (done) {
      // Set up a mock to return a null path string.
      var auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS', null);

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromEnvironmentVariable(function () {
        step(); // This should not get called.
      });

      assert.equal(false, handled);
      step(); // This should get called.
    });

    it('should return false when env var is empty string', function (done) {
      // Set up a mock to return an empty path string.
      var auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS', '');

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromEnvironmentVariable(function () {
        step(); // This should not get called.
      });

      assert.equal(false, handled);
      step(); // This should get called.
    });

    it('should handle invalid environment variable', function (done) {
      // Set up a mock to return a path to an invalid file.
      var auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS',
        './nonexistantfile.json');

      // The test ends successfully after 2 steps have completed.
      var step = doneWhen(done, 2);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromEnvironmentVariable(function (err) {
        assert.equal(true, err instanceof Error);
        step();
      });

      assert.equal(true, handled);
      step();
    });

    it('should handle valid environment variable', function (done) {
      // Set up a mock to return path to a valid credentials file.
      var auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS',
        './test/fixtures/private.json');

      // Read the contents of the file into a json object.
      var fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      var json = JSON.parse(fileContents);

      // The test ends successfully after 2 steps have completed.
      var step = doneWhen(done, 2);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromEnvironmentVariable(
        function (err, result) {
        assert.equal(null, err);
        assert.equal(json.private_key, result.key);
        assert.equal(json.client_email, result.email);
        assert.equal(null, result.keyFile);
        assert.equal(null, result.subject);
        assert.equal(null, result.scope);
        step();
      });

      assert.equal(true, handled);
      step();
    });
  });

  describe('._tryGetApplicationCredentialsFromWellKnownFile', function () {

    it('should build the correct directory for Windows', function () {
      var correctLocation = false;

      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(true);

      auth._getApplicationCredentialsFromFilePath = function (filePath) {
        if (filePath === 'foo:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
      };

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert.equal(true, handled);
      assert.equal(true, correctLocation);
    });

    it('should build the correct directory for non-Windows', function () {
      var correctLocation = false;

      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('linux');
      auth._fileExists = returns(true);


      auth._getApplicationCredentialsFromFilePath = function (filePath) {
        if (filePath === 'foo:.config:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
      };

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert.equal(true, handled);
      assert.equal(true, correctLocation);
    });

    it('should fail on Windows when APPDATA is not defined', function (done) {
      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', null);
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(true);
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function () {
        step(); // Should not get called.
      });

      assert.equal(false, handled);
      step(); // Should get called.
    });

    it('should fail on non-Windows when HOME is not defined', function (done) {
      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', null);
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('linux');
      auth._fileExists = returns(true);
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function () {
        step(); // Should not get called.
      });

      assert.equal(false, handled);
      step(); // Should get called.
    });

    it('should fail on Windows when file does not exist', function (done) {
      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(false);
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function () {
        step(); // Should not get called.
      });

      assert.equal(false, handled);
      step(); // Should get called.
    });

    it('should fail on non-Windows when file does not exist', function (done) {
      // Set up mocks.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('linux');
      auth._fileExists = returns(false);
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      var step = doneWhen(done, 1);

      // Execute.
      var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function () {
        step(); // Should not get called.
      });

      assert.equal(false, handled);
      step(); // Should get called.
    });
  });

  it('should succeeds on Windows', function (done) {
    // Set up mocks.
    var auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = returns('win32');
    auth._fileExists = returns(true);

    auth._getApplicationCredentialsFromFilePath = function (filePath, callback) {
      callback(null, 'hello');
    };

    // The test ends successfully after 2 steps have completed.
    var step = doneWhen(done, 2);

    // Execute.
    var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function (err, result) {
      assert.equal(null, err);
      assert.equal('hello', result);
      step();
    });

    assert.equal(true, handled);
    step();
  });

  it('should succeeds on non-Windows', function (done) {
    // Set up mocks.
    var auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = returns('linux');
    auth._fileExists = returns(true);

    auth._getApplicationCredentialsFromFilePath = function (filePath, callback) {
      callback(null, 'hello');
    };

    // The test ends successfully after 2 steps have completed.
    var step = doneWhen(done, 2);

    // Execute.
    var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function (err, result) {
      assert.equal(null, err);
      assert.equal('hello', result);
      step();
    });

    assert.equal(true, handled);
    step();
  });

  it('should pass along a failure on Windows', function (done) {
    // Set up mocks.
    var auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = returns('win32');
    auth._fileExists = returns(true);

    auth._getApplicationCredentialsFromFilePath = function (filePath, callback) {
      callback(new Error('hello'));
    };

    // The test ends successfully after 2 steps have completed.
    var step = doneWhen(done, 2);

    // Execute.
    var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function (err, result) {
      assert.equal('hello', err.message);
      assert.equal(null, result);
      step();
    });

    assert.equal(true, handled);
    step();
  });

  it('should pass along a failure on non-Windows', function (done) {
    // Set up mocks.
    var auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = returns('linux');
    auth._fileExists = returns(true);

    auth._getApplicationCredentialsFromFilePath = function (filePath, callback) {
      callback(new Error('hello'));
    };

    // The test ends successfully after 2 steps have completed.
    var step = doneWhen(done, 2);

    // Execute.
    var handled = auth._tryGetApplicationCredentialsFromWellKnownFile(function (err, result) {
      assert.equal('hello', err.message);
      assert.equal(null, result);
      step();
    });

    assert.equal(true, handled);
    step();
  });

  describe('.getApplicationDefault', function () {

    it('should return a new credential the first time and a cached credential the second time',
      function (done) {

        // The test ends successfully after 3 steps have completed.
        var step = doneWhen(done, 3);

        // Create a function which will set up a GoogleAuth instance to match on
        // an environment variable json file, but not on anything else.
        var setUpAuthForEnvironmentVariable = function(creds) {
          insertEnvironmentVariableIntoAuth(creds, 'GOOGLE_APPLICATION_CREDENTIALS',
            './test/fixtures/private.json');

          creds._fileExists = returns(false);
          creds._checkIsGCE = callsBack(false);
        };

        // Set up a new GoogleAuth and prepare it for local environment variable handling.
        var auth = new GoogleAuth();
        setUpAuthForEnvironmentVariable(auth);

        // Ask for credentials, the first time.
        auth.getApplicationDefault(function (err, result) {
          assert.equal(null, err);
          assert.notEqual(null, result);

          // Capture the returned credential.
          var cachedCredential = result;

          // Make sure our special test bit is not set yet, indicating that this is a new
          // credentials instance.
          assert.equal(null, cachedCredential.specialTestBit);

          // Now set the special test bit.
          cachedCredential.specialTestBit = 'monkey';

          // Step 1 has completed.
          step();

          // Ask for credentials again, from the same auth instance. We expect a cached instance
          // this time.
          auth.getApplicationDefault(function (err2, result2) {
            assert.equal(null, err2);
            assert.notEqual(null, result2);

            // Make sure the special test bit is set on the credentials we got back, indicating
            // that we got cached credentials. Also make sure the object instance is the same.
            assert.equal('monkey', result2.specialTestBit);
            assert.equal(cachedCredential, result2);

            // Now create a second GoogleAuth instance, and ask for credentials. We should
            // get a new credentials instance this time.
            var auth2 = new GoogleAuth();
            setUpAuthForEnvironmentVariable(auth2);

            // Step 2 has completed.
            step();

            auth2.getApplicationDefault(function (err3, result3) {
              assert.equal(null, err3);
              assert.notEqual(null, result3);

              // Make sure we get a new (non-cached) credential instance back.
              assert.equal(null, result3.specialTestBit);
              assert.notEqual(cachedCredential, result3);

              // Step 3 has completed.
              step();
            });
          });
        });
      });

    it('should use environment variable when it is set', function (done) {
      // We expect private.json to be the file that is used.
      var fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      var json = JSON.parse(fileContents);

      // Set up the creds.
      // * Environment variable is set up to point to private.json
      // * Well-known file is set up to point to private2.json
      // * Running on GCE is set to true.
      var auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS',
        './test/fixtures/private.json');
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(true);
      auth._checkIsGCE = callsBack(true);
      insertWellKnownFilePathIntoAuth(auth, 'foo:gcloud:application_default_credentials.json',
        './test/fixtures/private2.json');

      // Execute.
      auth.getApplicationDefault(function (err, result) {
        assert.equal(null, err);
        assert.equal(json.private_key, result.key);
        assert.equal(json.client_email, result.email);
        assert.equal(null, result.keyFile);
        assert.equal(null, result.subject);
        assert.equal(null, result.scope);
        done();
      });
    });

    it('should use well-known file when it is available and env var is not set', function (done) {
      // We expect private2.json to be the file that is used.
      var fileContents = fs.readFileSync('./test/fixtures/private2.json', 'utf-8');
      var json = JSON.parse(fileContents);

      // Set up the creds.
      // * Environment variable is not set.
      // * Well-known file is set up to point to private2.json
      // * Running on GCE is set to true.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(true);
      auth._checkIsGCE = callsBack(true);
      insertWellKnownFilePathIntoAuth(auth, 'foo:gcloud:application_default_credentials.json',
        './test/fixtures/private2.json');

      // Execute.
      auth.getApplicationDefault(function (err, result) {
        assert.equal(null, err);
        assert.equal(json.private_key, result.key);
        assert.equal(json.client_email, result.email);
        assert.equal(null, result.keyFile);
        assert.equal(null, result.subject);
        assert.equal(null, result.scope);
        done();
      });
    });

    it('should use GCE when well-known file and env var are not set', function (done) {
      // Set up the creds.
      // * Environment variable is not set.
      // * Well-known file is not set.
      // * Running on GCE is set to true.
      var auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = returns('win32');
      auth._fileExists = returns(false);
      auth._checkIsGCE = callsBack(true);

      // Execute.
      auth.getApplicationDefault(function (err, result) {
        assert.equal(null, err);

        // This indicates that we got a ComputeClient instance back, rather than a JWTClient.
        assert.equal('compute-placeholder', result.credentials.refresh_token);
        done();
      });
    });
  });

  describe('._checkIsGCE', function () {

    it('should set the _isGCE flag when running on GCE', function (done) {
      var auth = new GoogleAuth();

      // Mock the transport layer to return the correct header indicating that
      // we're running on GCE.
      auth.transporter = new MockTransporter(true);

      // Assert on the initial values.
      assert.notEqual(true, auth._isGCE);
      assert.notEqual(true, auth._checked_isGCE);

      // Execute.
      auth._checkIsGCE(function () {
        // Assert that the flags are set.
        assert.equal(true, auth._isGCE);
        assert.equal(true, auth._checked_isGCE);

        done();
      });
    });

    it('should not set the _isGCE flag when not running on GCE', function (done) {
      var auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(false);

      // Assert on the initial values.
      assert.notEqual(true, auth._isGCE);
      assert.notEqual(true, auth._checked_isGCE);

      // Execute.
      auth._checkIsGCE(function () {
        // Assert that the flags are set.
        assert.equal(false, auth._isGCE);
        assert.equal(true, auth._checked_isGCE);

        done();
      });
    });

    it('Does not execute the second time when running on GCE', function (done) {
      var auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(true);

      // Assert on the initial values.
      assert.notEqual(true, auth._checked_isGCE);
      assert.notEqual(true, auth._isGCE);
      assert.equal(0, auth.transporter.executionCount);

      // Execute.
      auth._checkIsGCE(function () {
        // Assert.
        assert.equal(true, auth._checked_isGCE);
        assert.equal(true, auth._isGCE);
        assert.equal(1, auth.transporter.executionCount);

        // Execute a second time, check that we still get the correct values back,
        // but the execution count has not rev'd again, indicating that we
        // got the cached values this time.
        auth._checkIsGCE(function () {
          assert.equal(true, auth._checked_isGCE);
          assert.equal(true, auth._isGCE);
          assert.equal(1, auth.transporter.executionCount);
        });

        done();
      });
    });

    it('Does not execute the second time when not running on GCE', function (done) {
      var auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(false);

      // Assert on the initial values.
      assert.notEqual(true, auth._checked_isGCE);
      assert.notEqual(true, auth._isGCE);
      assert.equal(0, auth.transporter.executionCount);

      // Execute.
      auth._checkIsGCE(function () {
        // Assert.
        assert.equal(true, auth._checked_isGCE);
        assert.equal(false, auth._isGCE);
        assert.equal(1, auth.transporter.executionCount);

        // Execute a second time, check that we still get the correct values back,
        // but the execution count has not rev'd again, indicating that we
        // got the cached values this time.
        auth._checkIsGCE(function () {
          assert.equal(true, auth._checked_isGCE);
          assert.equal(false, auth._isGCE);
          assert.equal(1, auth.transporter.executionCount);
        });

        done();
      });

      it('Returns false on transport error', function (done) {
        var auth = new GoogleAuth();

        // Mock the transport layer to indicate that we're not running on GCE, but also to
        // throw an error.
        auth.transporter = new MockTransporter(true, true);

        // Assert on the initial values.
        assert.notEqual(true, auth._checked_isGCE);
        assert.notEqual(true, auth._isGCE);

        // Execute.
        auth._checkIsGCE(function () {
          // Assert that _isGCE is set to false due to the error.
          assert.equal(true, auth._checked_isGCE);
          assert.equal(false, auth._isGCE);

          done();
        });
      });
    });
  });
});

// Mocks the transporter class to simulate GCE.
function MockTransporter(simulate_gce, throw_error) {
  this.isGCE = false;

  if (simulate_gce) {
    this.isGCE = true;
  }

  this.throw_error = throw_error;
  this.executionCount = 0;
}

MockTransporter.prototype.request = function(options, callback) {
  if (options.method === 'GET' && options.uri === 'http://metadata.google.internal') {

    this.executionCount += 1;

    var err = null;
    var response = { headers: { } };

    if (this.throw_error) {
      err = new Error('blah');
    } else if (this.isGCE) {
      response.headers['metadata-flavor'] = 'Google';
    }

    callback(err, null, response);
  } else {
    throw new Error('unexpected request');
  }
};
