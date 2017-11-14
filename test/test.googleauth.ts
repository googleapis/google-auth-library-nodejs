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

import * as assert from 'assert';
import * as fs from 'fs';
import * as nock from 'nock';
import * as path from 'path';
import * as request from 'request';

import {Compute} from '../src/auth/computeclient';
import {GoogleAuth} from '../src/auth/googleauth';
import {JWT, TokenOptions} from '../src/auth/jwtclient';
import {OAuth2Client} from '../src/auth/oauth2client';
import {UserRefreshClient} from '../src/auth/refreshclient';
import {BodyResponseCallback, DefaultTransporter} from '../src/transporters';

nock.disableNetConnect();

// Mocks the transporter class to simulate GCE.
class MockTransporter extends DefaultTransporter {
  isGCE: boolean;
  throwError?: boolean;
  executionCount: number;
  constructor(simulateGCE: boolean, throwError?: boolean) {
    super();
    this.isGCE = false;
    if (simulateGCE) {
      this.isGCE = true;
    }
    this.throwError = throwError;
    this.executionCount = 0;
  }
  request(options: request.OptionsWithUri, callback: BodyResponseCallback) {
    if (options.method === 'GET' &&
        options.uri === 'http://metadata.google.internal') {
      this.executionCount += 1;
      let err = null;
      const response = {headers: {} as request.Headers};
      if (this.throwError) {
        err = new Error('blah');
      } else if (this.isGCE) {
        response.headers['metadata-flavor'] = 'Google';
      }
      callback(err, null, response as request.RequestResponse);
      return {} as request.Request;
    } else {
      throw new Error('unexpected request');
    }
  }
}

// Creates a standard JSON auth object for testing.
function createJwtJSON() {
  return {
    private_key_id: 'key123',
    private_key: 'privatekey',
    client_email: 'hello@youarecool.com',
    client_id: 'client123',
    type: 'service_account'
  };
}

function createRefreshJSON() {
  return {
    client_secret: 'privatekey',
    client_id: 'client123',
    refresh_token: 'refreshtoken',
    type: 'authorized_user'
  };
}

// Matches the ending of a string.
function stringEndsWith(str: string, suffix: string) {
  return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

// Simulates a path join.
function pathJoin(item1: string, item2: string) {
  return item1 + ':' + item2;
}

// Returns the value.
function returns(value: {}) {
  return () => {
    return value;
  };
}

function callsBack(err: {}|null, value?: {}) {
  return (callback: Function) => {
    callback(err, value);
  };
}

// Blocks the GOOGLE_APPLICATION_CREDENTIALS by default. This is necessary in
// case it is actually set on the host machine executing the test.
function blockGoogleApplicationCredentialEnvironmentVariable(auth: GoogleAuth) {
  return insertEnvironmentVariableIntoAuth(
      auth, 'GOOGLE_APPLICATION_CREDENTIALS');
}

// Intercepts the specified environment variable, returning the specified value.
function insertEnvironmentVariableIntoAuth(
    auth: GoogleAuth, environmentVariableName: string,
    environmentVariableValue?: string) {
  const originalGetEnvironmentVariableFunction = auth._getEnv;
  auth._getEnv = (name: string) => {
    if (name === environmentVariableName) {
      return environmentVariableValue;
    }

    return originalGetEnvironmentVariableFunction(name);
  };
}

// Intercepts the specified file path and inserts the mock file path.
function insertWellKnownFilePathIntoAuth(
    auth: GoogleAuth, filePath: string, mockFilePath: string) {
  const originalMockWellKnownFilePathFunction = auth._mockWellKnownFilePath;

  auth._mockWellKnownFilePath = (kfpath: string) => {
    if (kfpath === filePath) {
      return mockFilePath;
    }

    return originalMockWellKnownFilePathFunction(filePath);
  };
}

const noop = () => undefined;

// Executes the doneCallback after the nTH call.
function doneWhen(doneCallback: Function, count: number) {
  let i = 0;

  return () => {
    ++i;

    if (i === count) {
      doneCallback();
    } else if (i > count) {
      throw new Error('Called too many times. Test error?');
    }
  };
}

describe('GoogleAuth', () => {
  describe('.fromJson', () => {

    it('should error on null json', (done) => {
      const auth = new GoogleAuth();
      // Test verifies invalid parameter tests, which requires cast to any.
      // tslint:disable-next-line no-any
      (auth as any).fromJSON(null, (err: Error) => {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    describe('.fromAPIKey', () => {
      const API_KEY = 'test-123';
      const STUB_PROJECT = 'my-awesome-project';
      describe('Exception behaviour', () => {
        let auth: GoogleAuth;
        before(() => {
          auth = new GoogleAuth();
        });
        it('Should error given an invalid api key', done => {
          // Test verifies invalid parameter tests, which requires cast to any.
          // tslint:disable-next-line no-any
          (auth as any).fromAPIKey(null, (err: Error) => {
            assert(err instanceof Error);
            done();
          });
        });
      });

      describe('Request/response lifecycle mocking', () => {
        const ENDPOINT = '/events:report';
        const RESPONSE_BODY = 'RESPONSE_BODY';
        const BASE_URL = [
          'https://clouderrorreporting.googleapis.com/v1beta1/projects',
          STUB_PROJECT
        ].join('/');
        let auth: GoogleAuth;
        beforeEach(() => {
          auth = new GoogleAuth();
          insertEnvironmentVariableIntoAuth(
              auth, 'GCLOUD_PROJECT', STUB_PROJECT);
        });
        afterEach(() => {
          nock.cleanAll();
        });

        describe('With no added query string parameters', () => {
          it('should make a request with the api key', (done) => {
            const fakeService =
                nock(BASE_URL)
                    .post(ENDPOINT)
                    .query({key: API_KEY})
                    .once()
                    .reply((uri) => {
                      assert(uri.indexOf('key=' + API_KEY) > -1);
                      return [200, RESPONSE_BODY];
                    });

            auth.fromAPIKey(API_KEY, (err, client) => {
              assert.strictEqual(err, null);
              if (client) {
                client.request(
                    {
                      url: BASE_URL + ENDPOINT,
                      method: 'POST',
                      json: '{"test": true}'
                    },
                    (err2, body) => {
                      assert.strictEqual(err2, null);
                      assert.strictEqual(RESPONSE_BODY, body);
                      fakeService.done();
                      done();
                    });
              }
            });
          });
        });

        describe('With preexisting query string parameters', () => {
          it('should make a request while preserving original parameters',
             (done) => {
               const OTHER_QS_PARAM = {test: 'abc'};
               const fakeService =
                   nock(BASE_URL)
                       .post(ENDPOINT)
                       .query({test: OTHER_QS_PARAM.test, key: API_KEY})
                       .once()
                       .reply((uri) => {
                         assert(uri.indexOf('key=' + API_KEY) > -1);
                         assert(
                             uri.indexOf('test=' + OTHER_QS_PARAM.test) > -1);
                         return [200, RESPONSE_BODY];
                       });
               auth.fromAPIKey(API_KEY, (err, client) => {
                 assert.strictEqual(err, null);
                 if (client) {
                   client.request(
                       {
                         url: BASE_URL + ENDPOINT,
                         method: 'POST',
                         json: '{"test": true}',
                         qs: OTHER_QS_PARAM
                       },
                       (err2, body) => {
                         assert.strictEqual(err2, null);
                         assert.strictEqual(RESPONSE_BODY, body);
                         fakeService.done();
                         done();
                       });
                 }
               });
             });
        });
      });
    });

    describe('JWT token', () => {

      it('should error on empty json', (done) => {
        const auth = new GoogleAuth();
        auth.fromJSON({}, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_email', (done) => {
        const json = createJwtJSON();
        delete json.client_email;

        const auth = new GoogleAuth();
        auth.fromJSON(json, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing private_key', (done) => {
        const json = createJwtJSON();
        delete json.private_key;

        const auth = new GoogleAuth();
        auth.fromJSON(json, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should create JWT with client_email', (done) => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        auth.fromJSON(json, (err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal(json.client_email, (result as JWT).email);
          }
          done();
        });
      });

      it('should create JWT with private_key', (done) => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        auth.fromJSON(json, (err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal(json.private_key, (result as JWT).key);
          }
          done();
        });
      });

      it('should create JWT with null scopes', (done) => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        auth.fromJSON(json, (err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal(null, (result as JWT).scopes);
          }
          done();
        });
      });

      it('should create JWT with null subject', (done) => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        auth.fromJSON(json, (err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal(null, (result as JWT).subject);
          }
          done();
        });
      });

      it('should create JWT with null keyFile', (done) => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        auth.fromJSON(json, (err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal(null, (result as JWT).keyFile);
          }
          done();
        });
      });
    });
    describe('Refresh token', () => {
      it('should error on empty json', (done) => {
        const auth = new GoogleAuth();
        const jwt = new auth.JWT();
        jwt.fromJSON({}, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_id', (done) => {
        const json = createRefreshJSON();
        delete json.client_id;

        const auth = new GoogleAuth();
        const jwt = new auth.JWT();
        jwt.fromJSON(json, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing client_secret', (done) => {
        const json = createRefreshJSON();
        delete json.client_secret;

        const auth = new GoogleAuth();
        const jwt = new auth.JWT();
        jwt.fromJSON(json, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });

      it('should error on missing refresh_token', done => {
        const json = createRefreshJSON();
        delete json.refresh_token;

        const auth = new GoogleAuth();
        const jwt = new auth.JWT();
        jwt.fromJSON(json, (err) => {
          assert.equal(true, err instanceof Error);
          done();
        });
      });
    });
  });

  describe('.fromStream', () => {

    it('should error on null stream', (done) => {
      const auth = new GoogleAuth();
      // Test verifies invalid parameter tests, which requires cast to any.
      // tslint:disable-next-line no-any
      (auth as any).fromStream(null, (err: Error) => {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should read the stream and create a jwt', (done) => {
      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Now open a stream on the same file.
      const stream = fs.createReadStream('./test/fixtures/private.json');

      // And pass it into the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream(stream, (err, result) => {
        assert.equal(null, err);
        assert(result);
        const jwt = result as JWT;
        if (jwt) {
          // Ensure that the correct bits were pulled from the stream.
          assert.equal(json.private_key, jwt.key);
          assert.equal(json.client_email, jwt.email);
          assert.equal(null, jwt.keyFile);
          assert.equal(null, jwt.subject);
          assert.equal(null, jwt.scope);
        }
        done();
      });
    });

    it('should read another stream and create a UserRefreshClient', (done) => {
      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/refresh.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Now open a stream on the same file.
      const stream = fs.createReadStream('./test/fixtures/refresh.json');

      // And pass it into the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream(stream, (err, result) => {
        assert.ifError(err);
        assert(result);
        // Ensure that the correct bits were pulled from the stream.
        if (result) {
          const rc = result as UserRefreshClient;
          assert.equal(json.client_id, rc._clientId);
          assert.equal(json.client_secret, rc._clientSecret);
          assert.equal(json.refresh_token, rc._refreshToken);
        }
        done();
      });
    });
  });

  describe('._getApplicationCredentialsFromFilePath', () => {

    it('should not error on valid symlink', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/goodlink', (err) => {
            assert.equal(false, err instanceof Error);
            done();
          });
    });

    it('should error on invalid symlink', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/badlink', (err) => {
            assert.equal(true, err instanceof Error);
            done();
          });
    });

    it('should error on valid link to invalid data', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/emptylink', (err) => {
            assert.equal(true, err instanceof Error);
            done();
          });
    });

    it('should error on null file path', (done) => {
      const auth = new GoogleAuth();
      (auth as
           // Test verifies invalid parameter tests, which requires cast to any.
           // tslint:disable-next-line no-any
           any)
          ._getApplicationCredentialsFromFilePath(null, (err: Error) => {
            assert.equal(true, err instanceof Error);
            done();
          });
    });

    it('should error on empty file path', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath('', (err) => {
        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should error on non-string file path', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          // Test verifies invalid parameter tests, which requires cast to any.
          // tslint:disable-next-line no-any
          (2 as any), (err: Error|null) => {
            assert.equal(true, err instanceof Error);
            done();
          });
    });

    it('should error on invalid file path', (done) => {
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          './nonexistantfile.json', (err) => {

            assert.equal(true, err instanceof Error);
            done();
          });
    });

    it('should error on directory', (done) => {
      // Make sure that the following path actually does point to a directory.
      const directory = './test/fixtures';
      assert.equal(true, fs.lstatSync(directory).isDirectory());

      // Execute.
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(directory, (err) => {

        assert.equal(true, err instanceof Error);
        done();
      });
    });

    it('should handle errors thrown from createReadStream', (done) => {
      // Set up a mock to throw from the createReadStream method.
      const auth = new GoogleAuth();
      auth._createReadStream = () => {
        throw new Error('Hans and Chewbacca');
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/private.json', (err) => {
            assert.equal(
                true,
                stringEndsWith(err ? err.message : '', 'Hans and Chewbacca'));
            done();
          });
    });

    it('should handle errors thrown from fromStream', (done) => {
      // Set up a mock to throw from the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream = () => {
        throw new Error('Darth Maul');
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/private.json', (err) => {

            assert.equal(
                true, stringEndsWith(err ? err.message : '', 'Darth Maul'));
            done();
          });
    });

    it('should handle errors passed from fromStream', (done) => {
      // Set up a mock to return an error from the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream = (stream, callback) => {
        if (callback) callback(new Error('Princess Leia'));
      };

      // Execute.
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/private.json', (err) => {

            assert.equal(
                true, stringEndsWith(err ? err.message : '', 'Princess Leia'));
            done();
          });
    });

    it('should correctly read the file and create a valid JWT', (done) => {
      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Now pass the same path to the auth loader.
      const auth = new GoogleAuth();
      auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/private.json', (err, result) => {
            assert.equal(null, err);
            assert(result);
            const jwt = result as JWT;
            if (result) {
              assert.equal(json.private_key, jwt.key);
              assert.equal(json.client_email, jwt.email);
              assert.equal(null, jwt.keyFile);
              assert.equal(null, jwt.subject);
              assert.equal(null, jwt.scope);
            }
            done();
          });
    });
  });

  describe('._tryGetApplicationCredentialsFromEnvironmentVariable', () => {

    it('should return false when env const is not set', (done) => {
      // Set up a mock to return a null path string.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS');

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromEnvironmentVariable(() => {
            step();  // This should not get called.
          });

      assert.equal(false, handled);
      step();  // This should get called.
    });

    it('should return false when env const is empty string', (done) => {
      // Set up a mock to return an empty path string.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS', '');

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromEnvironmentVariable(() => {
            step();  // This should not get called.
          });

      assert.equal(false, handled);
      step();  // This should get called.
    });

    it('should handle invalid environment variable', (done) => {
      // Set up a mock to return a path to an invalid file.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS', './nonexistantfile.json');

      // The test ends successfully after 2 steps have completed.
      const step = doneWhen(done, 2);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromEnvironmentVariable((err) => {
            assert.equal(true, err instanceof Error);
            step();
          });

      assert.equal(true, handled);
      step();
    });

    it('should handle valid environment variable', (done) => {
      // Set up a mock to return path to a valid credentials file.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS',
          './test/fixtures/private.json');

      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // The test ends successfully after 2 steps have completed.
      const step = doneWhen(done, 2);

      // Execute.
      const handled = auth._tryGetApplicationCredentialsFromEnvironmentVariable(
          (err, result) => {
            assert(result);
            assert.equal(null, err);
            const jwt = result as JWT;
            if (result) {
              assert.equal(json.private_key, jwt.key);
              assert.equal(json.client_email, jwt.email);
              assert.equal(null, jwt.keyFile);
              assert.equal(null, jwt.subject);
              assert.equal(null, jwt.scope);
            }
            step();
          });

      assert.equal(true, handled);
      step();
    });
  });

  describe('._tryGetApplicationCredentialsFromWellKnownFile', () => {

    it('should build the correct directory for Windows', () => {
      let correctLocation = false;

      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;

      auth._getApplicationCredentialsFromFilePath = (filePath) => {
        if (filePath === 'foo:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
      };

      // Execute.
      const handled = auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert.equal(true, handled);
      assert.equal(true, correctLocation);
    });

    it('should build the correct directory for non-Windows', () => {
      let correctLocation = false;

      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'linux';
      auth._fileExists = () => true;

      auth._getApplicationCredentialsFromFilePath = (filePath) => {
        if (filePath ===
            'foo:.config:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
      };

      // Execute.
      const handled = auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert.equal(true, handled);
      assert.equal(true, correctLocation);
    });

    it('should fail on Windows when APPDATA is not defined', (done) => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromWellKnownFile(() => {
            step();  // Should not get called.
          });

      assert.equal(false, handled);
      step();  // Should get called.
    });

    it('should fail on non-Windows when HOME is not defined', (done) => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'linux';
      auth._fileExists = () => true;
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromWellKnownFile(() => {
            step();  // Should not get called.
          });

      assert.equal(false, handled);
      step();  // Should get called.
    });

    it('should fail on Windows when file does not exist', (done) => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => false;
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromWellKnownFile(() => {
            step();  // Should not get called.
          });

      assert.equal(false, handled);
      step();  // Should get called.
    });

    it('should fail on non-Windows when file does not exist', (done) => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'linux';
      auth._fileExists = () => false;
      auth._getApplicationCredentialsFromFilePath = noop;

      // The test ends successfully after 1 step has completed.
      const step = doneWhen(done, 1);

      // Execute.
      const handled =
          auth._tryGetApplicationCredentialsFromWellKnownFile(() => {
            step();  // Should not get called.
          });

      assert.equal(false, handled);
      step();  // Should get called.
    });
  });

  it('should succeeds on Windows', (done) => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath, callback) => {
      if (callback) {
        const client = new JWT('hello');
        callback(null, client);
      }
    };

    // The test ends successfully after 2 steps have completed.
    const step = doneWhen(done, 2);

    // Execute.
    const handled =
        auth._tryGetApplicationCredentialsFromWellKnownFile((err, result) => {
          assert.equal(null, err);
          assert(result);
          if (result) {
            assert.equal('hello', (result as JWT).email);
          }
          step();
        });
    assert.equal(true, handled);
    step();
  });

  it('should succeeds on non-Windows', (done) => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'linux';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath, callback) => {
      if (callback) {
        callback(null, new JWT('hello'));
      }
    };

    // The test ends successfully after 2 steps have completed.
    const step = doneWhen(done, 2);

    // Execute.
    const handled =
        auth._tryGetApplicationCredentialsFromWellKnownFile((err, result) => {
          assert.equal(null, err);
          assert.equal('hello', (result as JWT).email);
          step();
        });

    assert.equal(true, handled);
    step();
  });

  it('should pass along a failure on Windows', (done) => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath, callback) => {
      if (callback) callback(new Error('hello'));
    };

    // The test ends successfully after 2 steps have completed.
    const step = doneWhen(done, 2);

    // Execute.
    const handled =
        auth._tryGetApplicationCredentialsFromWellKnownFile((err, result) => {
          assert(err);
          assert.equal('hello', err ? err.message : '');
          assert.equal(null, result);
          step();
        });

    assert.equal(true, handled);
    step();
  });

  it('should pass along a failure on non-Windows', (done) => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'linux';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath, callback) => {
      if (callback) callback(new Error('hello'));
    };

    // The test ends successfully after 2 steps have completed.
    const step = doneWhen(done, 2);

    // Execute.
    const handled =
        auth._tryGetApplicationCredentialsFromWellKnownFile((err, result) => {
          assert.equal('hello', err ? err.message : '');
          assert.equal(null, result);
          step();
        });

    assert.equal(true, handled);
    step();
  });

  describe('.getDefaultProjectId', () => {

    it('should return a new projectId the first time and a cached projectId the second time',
       (done) => {

         const fixedProjectId = 'my-awesome-project';
         // The test ends successfully after 3 steps have completed.
         const step = doneWhen(done, 3);

         // Create a function which will set up a GoogleAuth instance to match
         // on an environment variable json file, but not on anything else.
         const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
           insertEnvironmentVariableIntoAuth(
               creds, 'GCLOUD_PROJECT', fixedProjectId);

           creds._fileExists = () => false;
           creds._checkIsGCE =
               (callback: (err: Error|null, isGCE?: boolean) => void) => false;
         };

         // Set up a new GoogleAuth and prepare it for local environment
         // variable handling.
         const auth = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth);

         // Ask for credentials, the first time.
         auth.getDefaultProjectId((err, projectId) => {
           assert.equal(null, err);
           assert.equal(projectId, fixedProjectId);

           // Manually change the value of the cached projectId
           auth.cachedProjectId = 'monkey';

           // Step 1 has completed.
           step();

           // Ask for projectId again, from the same auth instance. We expect a
           // cached instance this time.
           auth.getDefaultProjectId((err2, projectId2) => {
             assert.equal(null, err2);

             // Make sure we get the changed cached projectId back
             assert.equal('monkey', projectId2);

             // Now create a second GoogleAuth instance, and ask for projectId.
             // We should get a new projectId instance this time.
             const auth2 = new GoogleAuth();
             setUpAuthForEnvironmentVariable(auth2);

             // Step 2 has completed.
             step();

             auth2.getDefaultProjectId((err3, projectId3) => {
               assert.equal(null, err3);
               assert.equal(projectId3, fixedProjectId);

               // Make sure we get a new (non-cached) projectId instance back.
               // Test verifies invalid parameter tests, which requires cast to
               // any.
               // tslint:disable-next-line no-any
               assert.equal((projectId3 as any).specialTestBit, undefined);

               // Step 3 has completed.
               step();
             });
           });
         });
       });

    it('should use GCLOUD_PROJECT environment variable when it is set',
       (done) => {
         const fixedProjectId = 'my-awesome-project';

         const auth = new GoogleAuth();
         insertEnvironmentVariableIntoAuth(
             auth, 'GCLOUD_PROJECT', fixedProjectId);

         // Execute.
         auth.getDefaultProjectId((err, projectId) => {
           assert.equal(err, null);
           assert.equal(projectId, fixedProjectId);
           done();
         });
       });

    it('should use GOOGLE_CLOUD_PROJECT environment variable when it is set',
       (done) => {
         const fixedProjectId = 'my-awesome-project';

         const auth = new GoogleAuth();
         insertEnvironmentVariableIntoAuth(
             auth, 'GOOGLE_CLOUD_PROJECT', fixedProjectId);

         // Execute.
         auth.getDefaultProjectId((err, projectId) => {
           assert.equal(err, null);
           assert.equal(projectId, fixedProjectId);
           done();
         });
       });

    it('should use GOOGLE_APPLICATION_CREDENTIALS file when it is available',
       (done) => {
         const fixedProjectId = 'my-awesome-project';

         const auth = new GoogleAuth();
         insertEnvironmentVariableIntoAuth(
             auth, 'GOOGLE_APPLICATION_CREDENTIALS',
             path.join(__dirname, '../../test/fixtures/private2.json'));

         // Execute.
         auth.getDefaultProjectId((err, projectId) => {
           assert.ifError(err);
           assert.equal(projectId, fixedProjectId);
           done();
         });
       });

    it('should use well-known file when it is available and env vars are not set',
       (done) => {
         const fixedProjectId = 'my-awesome-project';

         // Set up the creds.
         // * Environment variable is not set.
         // * Well-known file is set up to point to private2.json
         // * Running on GCE is set to true.
         const auth = new GoogleAuth();
         blockGoogleApplicationCredentialEnvironmentVariable(auth);
         auth._getSDKDefaultProjectId = (callback) => {
           callback(
               null, JSON.stringify({core: {project: fixedProjectId}}), null);
         };

         // Execute.
         auth.getDefaultProjectId((err, projectId) => {
           assert.equal(err, null);
           assert.equal(projectId, fixedProjectId);
           done();
         });
       });

    it('should use GCE when well-known file and env const are not set',
       (done) => {
         const fixedProjectId = 'my-awesome-project';
         const auth = new GoogleAuth();
         blockGoogleApplicationCredentialEnvironmentVariable(auth);
         auth._getSDKDefaultProjectId = (callback) => {
           callback(null, '', null);
         };
         // TODO: Provide a proper mock.
         // tslint:disable-next-line no-any
         (auth as any).transporter = {
           request: (opts: {}, callback?: BodyResponseCallback) => {
             return callback ? callback(
                                   null, fixedProjectId,
                                   {body: fixedProjectId, statusCode: 200} as
                                       request.RequestResponse) :
                               null;
           },
         };

         // Execute.
         auth.getDefaultProjectId((err, projectId) => {
           assert.equal(err, null);
           assert.equal(projectId, fixedProjectId);
           done();
         });
       });
  });

  describe('.getApplicationDefault', () => {

    it('should return a new credential the first time and a cached credential the second time',
       (done) => {

         // The test ends successfully after 3 steps have completed.
         const step = doneWhen(done, 3);

         // Create a function which will set up a GoogleAuth instance to match
         // on an environment variable json file, but not on anything else.
         const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
           insertEnvironmentVariableIntoAuth(
               creds, 'GOOGLE_APPLICATION_CREDENTIALS',
               './test/fixtures/private.json');

           creds._fileExists = () => false;
           creds._checkIsGCE =
               (callback: (err: Error|null, isGCE?: boolean) => void) => false;
         };

         // Set up a new GoogleAuth and prepare it for local environment
         // variable handling.
         const auth = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth);

         // Ask for credentials, the first time.
         auth.getApplicationDefault((err, result) => {
           assert.equal(null, err);
           assert.notEqual(null, result);

           // Capture the returned credential.
           const cachedCredential = result;

           // Make sure our special test bit is not set yet, indicating that
           // this is a new credentials instance.
           // Test verifies invalid parameter tests, which requires cast to any.
           // tslint:disable-next-line no-any
           assert.equal(null, (cachedCredential as any).specialTestBit);

           // Now set the special test bit.
           // Test verifies invalid parameter tests, which requires cast to any.
           // tslint:disable-next-line no-any
           (cachedCredential as any).specialTestBit = 'monkey';

           // Step 1 has completed.
           step();

           // Ask for credentials again, from the same auth instance. We expect
           // a cached instance this time.
           auth.getApplicationDefault((err2, result2) => {
             assert.equal(null, err2);
             assert.notEqual(null, result2);

             // Make sure the special test bit is set on the credentials we got
             // back, indicating that we got cached credentials. Also make sure
             // the object instance is the same.
             // Test verifies invalid parameter tests, which requires cast to
             // any.
             // tslint:disable-next-line no-any
             assert.equal('monkey', (result2 as any).specialTestBit);
             assert.equal(cachedCredential, result2);

             // Now create a second GoogleAuth instance, and ask for
             // credentials. We should get a new credentials instance this time.
             const auth2 = new GoogleAuth();
             setUpAuthForEnvironmentVariable(auth2);

             // Step 2 has completed.
             step();

             auth2.getApplicationDefault((err3, result3) => {
               assert.equal(null, err3);
               assert.notEqual(null, result3);

               // Make sure we get a new (non-cached) credential instance back.
               // Test verifies invalid parameter tests, which requires cast to
               // any.
               // tslint:disable-next-line no-any
               assert.equal(null, (result3 as any).specialTestBit);
               assert.notEqual(cachedCredential, result3);

               // Step 3 has completed.
               step();
             });
           });
         });
       });

    it('should use environment variable when it is set', (done) => {
      // We expect private.json to be the file that is used.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Set up the creds.
      // * Environment variable is set up to point to private.json
      // * Well-known file is set up to point to private2.json
      // * Running on GCE is set to true.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS',
          './test/fixtures/private.json');
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;

      auth._checkIsGCE = callsBack(null, true);
      insertWellKnownFilePathIntoAuth(
          auth, 'foo:gcloud:application_default_credentials.json',
          './test/fixtures/private2.json');

      // Execute.
      auth.getApplicationDefault((err, result) => {
        const client = result as JWT;
        assert.equal(null, err);
        assert.equal(json.private_key, client.key);
        assert.equal(json.client_email, client.email);
        assert.equal(null, client.keyFile);
        assert.equal(null, client.subject);
        assert.equal(null, client.scope);
        done();
      });
    });

    it('should use well-known file when it is available and env const is not set',
       (done) => {
         // We expect private2.json to be the file that is used.
         const fileContents =
             fs.readFileSync('./test/fixtures/private2.json', 'utf-8');
         const json = JSON.parse(fileContents);

         // Set up the creds.
         // * Environment variable is not set.
         // * Well-known file is set up to point to private2.json
         // * Running on GCE is set to true.
         const auth = new GoogleAuth();
         blockGoogleApplicationCredentialEnvironmentVariable(auth);
         insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
         auth._pathJoin = pathJoin;
         auth._osPlatform = () => 'win32';
         auth._fileExists = () => true;
         auth._checkIsGCE =
             (callback: (err: Error|null, isGCE?: boolean) => void) => true;
         insertWellKnownFilePathIntoAuth(
             auth, 'foo:gcloud:application_default_credentials.json',
             './test/fixtures/private2.json');

         // Execute.
         auth.getApplicationDefault((err, result) => {
           assert.equal(null, err);
           const client = result as JWT;
           assert.equal(json.private_key, client.key);
           assert.equal(json.client_email, client.email);
           assert.equal(null, client.keyFile);
           assert.equal(null, client.subject);
           assert.equal(null, client.scope);
           done();
         });
       });

    it('should use GCE when well-known file and env const are not set',
       (done) => {
         // Set up the creds.
         // * Environment variable is not set.
         // * Well-known file is not set.
         // * Running on GCE is set to true.
         const auth = new GoogleAuth();
         blockGoogleApplicationCredentialEnvironmentVariable(auth);
         insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
         auth._pathJoin = pathJoin;
         auth._osPlatform = () => 'win32';
         auth._fileExists = () => false;
         auth._checkIsGCE = callsBack(null, true);

         // Execute.
         auth.getApplicationDefault((err, result) => {
           assert.equal(null, err);

           // This indicates that we got a ComputeClient instance back, rather
           // than a JWTClient.
           assert.equal(
               'compute-placeholder', result.credentials.refresh_token);
           done();
         });
       });

    it('should report GCE error when checking for GCE fails', (done) => {
      // Set up the creds.
      // * Environment variable is not set.
      // * Well-known file is not set.
      // * Running on GCE is set to true.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => false;
      auth._checkIsGCE = callsBack(new Error('fake error'), undefined);

      // Execute.
      auth.getApplicationDefault((err, result) => {
        assert(err instanceof Error);
        assert.equal(result, undefined);
        done();
      });
    });

    it('should also get project ID', (done) => {
      // We expect private.json to be the file that is used.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);
      const testProjectId = 'my-awesome-project';

      // Set up the creds.
      // * Environment variable is set up to point to private.json
      // * Well-known file is set up to point to private2.json
      // * Running on GCE is set to true.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS',
          './test/fixtures/private.json');
      insertEnvironmentVariableIntoAuth(auth, 'GCLOUD_PROJECT', testProjectId);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;
      auth._checkIsGCE =
          (callback: (err: Error|null, isGCE?: boolean) => void) => true;
      insertWellKnownFilePathIntoAuth(
          auth, 'foo:gcloud:application_default_credentials.json',
          './test/fixtures/private2.json');

      // Execute.
      auth.getApplicationDefault((err, result, projectId) => {
        assert.equal(null, err);
        const client = result as JWT;
        assert.equal(json.private_key, client.key);
        assert.equal(json.client_email, client.email);
        assert.equal(projectId, testProjectId);
        assert.equal(null, client.keyFile);
        assert.equal(null, client.subject);
        assert.equal(null, client.scope);
        done();
      });
    });
  });

  describe('._checkIsGCE', () => {

    it('should set the _isGCE flag when running on GCE', (done) => {
      const auth = new GoogleAuth();

      // Mock the transport layer to return the correct header indicating that
      // we're running on GCE.
      auth.transporter = new MockTransporter(true);

      // Assert on the initial values.
      assert.notEqual(true, auth.isGCE);

      // Execute.
      auth._checkIsGCE(() => {
        // Assert that the flags are set.
        assert.equal(true, auth.isGCE);
        done();
      });
    });

    it('should not set the _isGCE flag when not running on GCE', (done) => {
      const auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(false);

      // Assert on the initial values.
      assert.notEqual(true, auth.isGCE);

      // Execute.
      auth._checkIsGCE(() => {
        // Assert that the flags are set.
        assert.equal(false, auth.isGCE);
        done();
      });
    });

    it('Does not execute the second time when running on GCE', (done) => {
      const auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(true);

      // Assert on the initial values.
      assert.notEqual(true, auth.isGCE);
      assert.equal(0, (auth.transporter as MockTransporter).executionCount);

      // Execute.
      auth._checkIsGCE(() => {
        // Assert.
        assert.equal(true, auth.isGCE);
        assert.equal(1, (auth.transporter as MockTransporter).executionCount);

        // Execute a second time, check that we still get the correct values
        // back, but the execution count has not rev'd again, indicating that we
        // got the cached values this time.
        auth._checkIsGCE(() => {
          assert.equal(true, auth.isGCE);
          assert.equal(1, (auth.transporter as MockTransporter).executionCount);
        });

        done();
      });
    });

    it('Does not execute the second time when not running on GCE', (done) => {
      const auth = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE.
      auth.transporter = new MockTransporter(false);

      // Assert on the initial values.
      assert.notEqual(true, auth.isGCE);
      assert.equal(0, (auth.transporter as MockTransporter).executionCount);

      // Execute.
      auth._checkIsGCE(() => {
        // Assert.
        assert.equal(false, auth.isGCE);
        assert.equal(1, (auth.transporter as MockTransporter).executionCount);

        // Execute a second time, check that we still get the correct values
        // back, but the execution count has not rev'd again, indicating that we
        // got the cached values this time.
        auth._checkIsGCE(() => {
          assert.equal(false, auth.isGCE);
          assert.equal(1, (auth.transporter as MockTransporter).executionCount);
        });

        done();
      });

      it('Returns false on transport error', (done2) => {
        const auth2 = new GoogleAuth();

        // Mock the transport layer to indicate that we're not running on GCE,
        // but also to throw an error.
        auth2.transporter = new MockTransporter(true, true);

        // Assert on the initial values.
        assert.notEqual(true, auth2.isGCE);

        // Execute.
        auth2._checkIsGCE(() => {
          // Assert that _isGCE is set to false due to the error.
          assert.equal(false, auth2.isGCE);

          done2();
        });
      });
    });
  });
});
