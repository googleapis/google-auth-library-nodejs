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
import {AxiosPromise, AxiosRequestConfig, AxiosResponse} from 'axios';
import * as fs from 'fs';
import * as http from 'http';
import * as nock from 'nock';
import * as path from 'path';
import * as stream from 'stream';

import {DefaultTransporter, GoogleAuth, JWT, UserRefreshClient} from '../src/index';
import {BodyResponseCallback} from '../src/transporters';

nock.disableNetConnect();

afterEach(() => {
  nock.cleanAll();
});

function createIsGCENock(isGCE = true) {
  nock('http://metadata.google.internal').get('/').reply(200, null, {
    'metadata-flavor': 'Google'
  });
}

function createGetProjectIdNock(projectId: string) {
  nock('http://169.254.169.254')
      .get('/computeMetadata/v1/project/project-id')
      .reply(200, projectId);
}

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
  request<T>(opts: AxiosRequestConfig): AxiosPromise<T>;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      void;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      AxiosPromise<T>|void {
    if (opts.url === 'http://metadata.google.internal') {
      this.executionCount += 1;
      let err = null;
      const response = {headers: {} as http.IncomingHttpHeaders} as
          AxiosResponse;
      if (this.throwError) {
        err = new Error('blah');
      } else if (this.isGCE) {
        response.headers['metadata-flavor'] = 'Google';
      }
      if (callback) {
        return callback(err, response);
      } else {
        return Promise.resolve(response);
      }
    } else {
      const err = new Error('unexpected request');
      if (callback) {
        return callback(err);
      } else {
        throw err;
      }
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

describe('GoogleAuth', () => {
  describe('.fromJson', () => {
    it('should error on null json', () => {
      const auth = new GoogleAuth();
      assert.throws(() => {
        // Test verifies invalid parameter tests, which requires cast to any.
        // tslint:disable-next-line no-any
        (auth as any).fromJSON(null);
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
        it('Should error given an invalid api key', () => {
          assert.throws(() => {
            // Test verifies invalid parameter tests, which requires cast to
            // any.
            // tslint:disable-next-line no-any
            (auth as any).fromAPIKey(null);
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

            const client = auth.fromAPIKey(API_KEY);
            client.request(
                {
                  url: BASE_URL + ENDPOINT,
                  method: 'POST',
                  data: {'test': true}
                },
                (err2, res) => {
                  assert.strictEqual(err2, null);
                  assert.strictEqual(RESPONSE_BODY, res!.data);
                  fakeService.done();
                  done();
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
               const client = auth.fromAPIKey(API_KEY);
               client.request(
                   {
                     url: BASE_URL + ENDPOINT,
                     method: 'POST',
                     data: {'test': true},
                     params: OTHER_QS_PARAM
                   },
                   (err2, res) => {
                     assert.strictEqual(err2, null);
                     assert.strictEqual(RESPONSE_BODY, res!.data);
                     fakeService.done();
                     done();
                   });
             });
        });
      });
    });

    describe('JWT token', () => {
      it('should error on empty json', () => {
        const auth = new GoogleAuth();
        assert.throws(() => {
          auth.fromJSON({});
        });
      });

      it('should error on missing client_email', () => {
        const json = createJwtJSON();
        delete json.client_email;

        const auth = new GoogleAuth();
        assert.throws(() => {
          auth.fromJSON(json);
        });
      });

      it('should error on missing private_key', () => {
        const json = createJwtJSON();
        delete json.private_key;

        const auth = new GoogleAuth();
        assert.throws(() => {
          auth.fromJSON(json);
        });
      });

      it('should create JWT with client_email', () => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        const result = auth.fromJSON(json);
        assert.equal(json.client_email, (result as JWT).email);
      });

      it('should create JWT with private_key', () => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        const result = auth.fromJSON(json);
        assert.equal(json.private_key, (result as JWT).key);
      });

      it('should create JWT with null scopes', () => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        const result = auth.fromJSON(json);
        assert.equal(null, (result as JWT).scopes);
      });

      it('should create JWT with null subject', () => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        const result = auth.fromJSON(json);
        assert.equal(null, (result as JWT).subject);
      });

      it('should create JWT with null keyFile', () => {
        const json = createJwtJSON();
        const auth = new GoogleAuth();
        const result = auth.fromJSON(json);
        assert.equal(null, (result as JWT).keyFile);
      });
    });

    describe('Refresh token', () => {
      it('should error on empty json', () => {
        const jwt = new JWT();
        assert.throws(() => {
          jwt.fromJSON({});
        });
      });

      it('should error on missing client_id', () => {
        const json = createRefreshJSON();
        delete json.client_id;
        const jwt = new JWT();
        assert.throws(() => {
          jwt.fromJSON(json);
        });
      });

      it('should error on missing client_secret', () => {
        const json = createRefreshJSON();
        delete json.client_secret;
        const jwt = new JWT();
        assert.throws(() => {
          jwt.fromJSON(json);
        });
      });

      it('should error on missing refresh_token', () => {
        const json = createRefreshJSON();
        delete json.refresh_token;
        const jwt = new JWT();
        assert.throws(() => {
          jwt.fromJSON(json);
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
        const jwt = result as JWT;
        // Ensure that the correct bits were pulled from the stream.
        assert.equal(json.private_key, jwt.key);
        assert.equal(json.client_email, jwt.email);
        assert.equal(null, jwt.keyFile);
        assert.equal(null, jwt.subject);
        assert.equal(null, jwt.scope);
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
        // Ensure that the correct bits were pulled from the stream.
        const rc = result as UserRefreshClient;
        assert.equal(json.client_id, rc._clientId);
        assert.equal(json.client_secret, rc._clientSecret);
        assert.equal(json.refresh_token, rc._refreshToken);
        done();
      });
    });
  });

  describe('._getApplicationCredentialsFromFilePath', () => {
    it('should not error on valid symlink', async () => {
      const auth = new GoogleAuth();
      await auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/goodlink');
    });

    it('should error on invalid symlink', async () => {
      const auth = new GoogleAuth();
      try {
        await auth._getApplicationCredentialsFromFilePath(
            './test/fixtures/badlink');
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on valid link to invalid data', async () => {
      const auth = new GoogleAuth();
      try {
        await auth._getApplicationCredentialsFromFilePath(
            './test/fixtures/emptylink');
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on null file path', async () => {
      const auth = new GoogleAuth();
      try {
        // Test verifies invalid parameter tests, which requires cast to any.
        // tslint:disable-next-line no-any
        await (auth as any)._getApplicationCredentialsFromFilePath(null);
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on empty file path', async () => {
      const auth = new GoogleAuth();
      try {
        await auth._getApplicationCredentialsFromFilePath('');
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on non-string file path', async () => {
      const auth = new GoogleAuth();
      try {
        // Test verifies invalid parameter tests, which requires cast to any.
        // tslint:disable-next-line no-any
        await auth._getApplicationCredentialsFromFilePath(2 as any);
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on invalid file path', async () => {
      const auth = new GoogleAuth();
      try {
        await auth._getApplicationCredentialsFromFilePath(
            './nonexistantfile.json');
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should error on directory', async () => {
      // Make sure that the following path actually does point to a directory.
      const directory = './test/fixtures';
      assert.equal(true, fs.lstatSync(directory).isDirectory());
      const auth = new GoogleAuth();
      try {
        await auth._getApplicationCredentialsFromFilePath(directory);
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should handle errors thrown from createReadStream', async () => {
      // Set up a mock to throw from the createReadStream method.
      const auth = new GoogleAuth();
      auth._createReadStream = () => {
        throw new Error('Han and Chewbacca');
      };

      try {
        await auth._getApplicationCredentialsFromFilePath(
            './test/fixtures/private.json');
      } catch (e) {
        assert.equal(true, stringEndsWith(e.message, 'Han and Chewbacca'));
        return;
      }
      assert.fail('failed to throw');
    });

    it('should handle errors thrown from fromStream', async () => {
      // Set up a mock to throw from the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream = () => {
        throw new Error('Darth Maul');
      };
      try {
        await auth._getApplicationCredentialsFromFilePath(
            './test/fixtures/private.json');
      } catch (e) {
        assert(stringEndsWith(e.message, 'Darth Maul'));
        return;
      }
      assert.fail('failed to throw');
    });

    it('should handle errors passed from fromStream', async () => {
      // Set up a mock to return an error from the fromStream method.
      const auth = new GoogleAuth();
      auth.fromStream = (streamInput: stream.Readable) => {
        throw new Error('Princess Leia');
      };

      try {
        await auth._getApplicationCredentialsFromFilePath(
            './test/fixtures/private.json');
      } catch (e) {
        assert(stringEndsWith(e.message, 'Princess Leia'));
        return;
      }
      assert.fail('failed to throw');
    });

    it('should correctly read the file and create a valid JWT', async () => {
      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Now pass the same path to the auth loader.
      const auth = new GoogleAuth();
      const result = await auth._getApplicationCredentialsFromFilePath(
          './test/fixtures/private.json');
      assert(result);
      const jwt = result as JWT;
      assert.equal(json.private_key, jwt.key);
      assert.equal(json.client_email, jwt.email);
      assert.equal(null, jwt.keyFile);
      assert.equal(null, jwt.subject);
      assert.equal(null, jwt.scope);
    });
  });

  describe('._tryGetApplicationCredentialsFromEnvironmentVariable', () => {
    it('should return null when env const is not set', async () => {
      // Set up a mock to return a null path string.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS');
      const client =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert.equal(client, null);
    });

    it('should return null when env const is empty string', async () => {
      // Set up a mock to return an empty path string.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS', '');
      const client =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert.equal(client, null);
    });

    it('should handle invalid environment variable', async () => {
      // Set up a mock to return a path to an invalid file.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS', './nonexistantfile.json');

      try {
        await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      } catch (e) {
        return;
      }
      assert.fail('failed to throw');
    });

    it('should handle valid environment variable', async () => {
      // Set up a mock to return path to a valid credentials file.
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS',
          './test/fixtures/private.json');

      // Read the contents of the file into a json object.
      const fileContents =
          fs.readFileSync('./test/fixtures/private.json', 'utf-8');
      const json = JSON.parse(fileContents);

      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      const jwt = result as JWT;
      assert.equal(json.private_key, jwt.key);
      assert.equal(json.client_email, jwt.email);
      assert.equal(null, jwt.keyFile);
      assert.equal(null, jwt.subject);
      assert.equal(null, jwt.scope);
    });
  });

  describe('._tryGetApplicationCredentialsFromWellKnownFile', () => {
    it('should build the correct directory for Windows', async () => {
      let correctLocation = false;

      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;

      auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
        if (filePath === 'foo:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
        return Promise.resolve({} as JWT);
      };

      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert(result);
      assert(correctLocation);
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

      auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
        if (filePath ===
            'foo:.config:gcloud:application_default_credentials.json') {
          correctLocation = true;
        }
        return Promise.resolve({} as JWT);
      };

      // Execute.
      const client = auth._tryGetApplicationCredentialsFromWellKnownFile();

      assert(client);
      assert(correctLocation);
    });

    it('should fail on Windows when APPDATA is not defined', async () => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;
      auth._getApplicationCredentialsFromFilePath =
          (filePath: string): Promise<JWT|UserRefreshClient> => {
            return Promise.resolve({} as JWT);
          };
      const result =
          await auth._tryGetApplicationCredentialsFromWellKnownFile();
      assert.equal(null, result);
    });

    it('should fail on non-Windows when HOME is not defined', async () => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'linux';
      auth._fileExists = () => true;
      auth._getApplicationCredentialsFromFilePath =
          (filePath: string): Promise<JWT|UserRefreshClient> => {
            return Promise.resolve({} as JWT);
          };

      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromWellKnownFile();
      assert.equal(null, result);
    });

    it('should fail on Windows when file does not exist', async () => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => false;
      auth._getApplicationCredentialsFromFilePath =
          (filePath: string): Promise<JWT|UserRefreshClient> => {
            return Promise.resolve({} as JWT);
          };

      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromWellKnownFile();
      assert.equal(null, result);
    });

    it('should fail on non-Windows when file does not exist', async () => {
      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'linux';
      auth._fileExists = () => false;
      auth._getApplicationCredentialsFromFilePath =
          (filePath: string): Promise<JWT|UserRefreshClient> => {
            return Promise.resolve({} as JWT);
          };

      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromWellKnownFile();
      assert.equal(null, result);
    });
  });

  it('should succeeds on Windows', async () => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;
    auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
      return Promise.resolve(new JWT('hello'));
    };

    // Execute.
    const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
    assert.equal('hello', (result as JWT)!.email);
  });

  it('should succeeds on non-Windows', async () => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'linux';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
      return Promise.resolve(new JWT('hello'));
    };

    // Execute.
    const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
    assert.equal('hello', (result as JWT).email);
  });

  it('should pass along a failure on Windows', async () => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
      throw new Error('hello');
    };

    // Execute.
    try {
      await auth._tryGetApplicationCredentialsFromWellKnownFile();
    } catch (e) {
      assert(e);
      assert.equal('hello', e.message);
      return;
    }
    assert.fail('failed to throw');
  });

  it('should pass along a failure on non-Windows', async () => {
    // Set up mocks.
    const auth = new GoogleAuth();
    blockGoogleApplicationCredentialEnvironmentVariable(auth);
    insertEnvironmentVariableIntoAuth(auth, 'HOME', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'linux';
    auth._fileExists = () => true;

    auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
      throw new Error('hello');
    };

    // Execute.
    try {
      await auth._tryGetApplicationCredentialsFromWellKnownFile();
    } catch (e) {
      assert.equal('hello', e.message);
      return;
    }
    assert.fail('failed to throw');
  });

  describe('.getDefaultProjectId', () => {
    it('should return a new projectId the first time and a cached projectId the second time',
       async () => {
         const fixedProjectId = 'my-awesome-project';

         // Create a function which will set up a GoogleAuth instance to match
         // on an environment variable json file, but not on anything else.
         const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
           insertEnvironmentVariableIntoAuth(
               creds, 'GCLOUD_PROJECT', fixedProjectId);

           creds._fileExists = () => false;
           creds._checkIsGCE = async () => Promise.resolve(false);
         };

         // Set up a new GoogleAuth and prepare it for local environment
         // variable handling.
         const auth = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth);

         // Ask for credentials, the first time.
         const projectId = await auth.getDefaultProjectId();
         assert.equal(projectId, fixedProjectId);

         // Manually change the value of the cached projectId
         auth.cachedProjectId = 'monkey';

         // Ask for projectId again, from the same auth instance. We expect a
         // cached instance this time.
         const projectId2 = await auth.getDefaultProjectId();

         // Make sure we get the changed cached projectId back
         assert.equal('monkey', projectId2);

         // Now create a second GoogleAuth instance, and ask for projectId.
         // We should get a new projectId instance this time.
         const auth2 = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth2);

         const projectId3 = await auth2.getDefaultProjectId();
         assert.equal(projectId3, fixedProjectId);

         // Make sure we get a new (non-cached) projectId instance back.
         // Test verifies invalid parameter tests, which requires cast to
         // any.
         // tslint:disable-next-line no-any
         assert.equal((projectId3 as any).specialTestBit, undefined);
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
       auth._getSDKDefaultProjectId = () => {
         return Promise.resolve({
           stdout: JSON.stringify({
             configuration: {properties: {core: {project: fixedProjectId}}}
           }),
           stderr: null
         });
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
       auth._getSDKDefaultProjectId = () => {
         return Promise.resolve({stdout: '', stderr: null});
       };
       createGetProjectIdNock(fixedProjectId);

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
     async () => {
       // Create a function which will set up a GoogleAuth instance to match
       // on an environment variable json file, but not on anything else.
       const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
         insertEnvironmentVariableIntoAuth(
             creds, 'GOOGLE_APPLICATION_CREDENTIALS',
             './test/fixtures/private.json');

         creds._fileExists = () => false;
         creds._checkIsGCE = () => Promise.resolve(false);
       };

       // Set up a new GoogleAuth and prepare it for local environment
       // variable handling.
       const auth = new GoogleAuth();
       setUpAuthForEnvironmentVariable(auth);

       // Ask for credentials, the first time.
       const result = await auth.getApplicationDefault();
       assert.notEqual(null, result);

       // Capture the returned credential.
       const cachedCredential = result.credential;

       // Make sure our special test bit is not set yet, indicating that
       // this is a new credentials instance.
       // Test verifies invalid parameter tests, which requires cast to any.
       // tslint:disable-next-line no-any
       assert.equal(null, (cachedCredential as any).specialTestBit);

       // Now set the special test bit.
       // Test verifies invalid parameter tests, which requires cast to any.
       // tslint:disable-next-line no-any
       (cachedCredential as any).specialTestBit = 'monkey';

       // Ask for credentials again, from the same auth instance. We expect
       // a cached instance this time.
       const result2 = (await auth.getApplicationDefault()).credential;
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

       const result3 = (await auth2.getApplicationDefault()).credential;
       assert.notEqual(null, result3);

       // Make sure we get a new (non-cached) credential instance back.
       // Test verifies invalid parameter tests, which requires cast to
       // any.
       // tslint:disable-next-line no-any
       assert.equal(null, (result3 as any).specialTestBit);
       assert.notEqual(cachedCredential, result3);
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
        auth, 'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;

    auth._checkIsGCE = () => Promise.resolve(true);
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
       auth._checkIsGCE = () => Promise.resolve(true);
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
       auth._checkIsGCE = () => Promise.resolve(true);

       // Execute.
       auth.getApplicationDefault((err, result) => {
         assert.equal(null, err);
         // This indicates that we got a ComputeClient instance back, rather
         // than a JWTClient.
         assert.equal('compute-placeholder', result!.credentials.refresh_token);
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
    auth._checkIsGCE = () => {
      throw new Error('fake error');
    };

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
        auth, 'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
    insertEnvironmentVariableIntoAuth(auth, 'GCLOUD_PROJECT', testProjectId);
    insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;
    auth._checkIsGCE = () => Promise.resolve(true);
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
  it('should set the _isGCE flag when running on GCE', async () => {
    const auth = new GoogleAuth();

    // Mock the transport layer to return the correct header indicating that
    // we're running on GCE.
    auth.transporter = new MockTransporter(true);

    // Assert on the initial values.
    assert.notEqual(true, auth.isGCE);

    // Execute.
    const isGCE = await auth._checkIsGCE();
    assert.equal(true, auth.isGCE);
  });

  it('should not set the _isGCE flag when not running on GCE', async () => {
    const auth = new GoogleAuth();

    // Mock the transport layer to indicate that we're not running on GCE.
    auth.transporter = new MockTransporter(false);

    // Assert on the initial values.
    assert.notEqual(true, auth.isGCE);

    // Execute.
    const isGCE = await auth._checkIsGCE();
    // Assert that the flags are set.
    assert.equal(false, auth.isGCE);
  });

  it('Does not execute the second time when running on GCE', async () => {
    const auth = new GoogleAuth();

    // Mock the transport layer to indicate that we're not running on GCE.
    auth.transporter = new MockTransporter(true);

    // Assert on the initial values.
    assert.notEqual(true, auth.isGCE);
    assert.equal(0, (auth.transporter as MockTransporter).executionCount);

    // Execute.
    await auth._checkIsGCE();
    // Assert.
    assert.equal(true, auth.isGCE);
    assert.equal(1, (auth.transporter as MockTransporter).executionCount);

    // Execute a second time, check that we still get the correct values
    // back, but the execution count has not rev'd again, indicating that we
    // got the cached values this time.
    const isGCE2 = await auth._checkIsGCE();
    assert.equal(true, auth.isGCE);
    assert.equal(1, (auth.transporter as MockTransporter).executionCount);
  });

  it('Does not execute the second time when not running on GCE', async () => {
    const auth = new GoogleAuth();

    // Mock the transport layer to indicate that we're not running on GCE.
    auth.transporter = new MockTransporter(false);

    // Assert on the initial values.
    assert.notEqual(true, auth.isGCE);
    assert.equal(0, (auth.transporter as MockTransporter).executionCount);

    // Execute.
    await auth._checkIsGCE();
    // Assert.
    assert.equal(false, auth.isGCE);
    assert.equal(1, (auth.transporter as MockTransporter).executionCount);

    // Execute a second time, check that we still get the correct values
    // back, but the execution count has not rev'd again, indicating that we
    // got the cached values this time.
    await auth._checkIsGCE();
    assert.equal(false, auth.isGCE);
    assert.equal(1, (auth.transporter as MockTransporter).executionCount);


    it('Returns false on transport error', async () => {
      const auth2 = new GoogleAuth();

      // Mock the transport layer to indicate that we're not running on GCE,
      // but also to throw an error.
      auth2.transporter = new MockTransporter(true, true);

      // Assert on the initial values.
      assert.notEqual(true, auth2.isGCE);

      // Execute.
      await auth2._checkIsGCE();
      // Assert that _isGCE is set to false due to the error.
      assert.equal(false, auth2.isGCE);
    });
  });

  describe('.getCredentials', () => {
    it('should get metadata from the server when running on GCE', async () => {
      const auth = new GoogleAuth();

      createIsGCENock();
      const isGCE = await auth._checkIsGCE();

      // Assert that the flags are set.
      assert.equal(true, auth.isGCE);

      const response = {
        default: {
          email: 'test-creds@test-creds.iam.gserviceaccount.com',
          private_key: null
        }
      };

      nock('http://metadata.google.internal')
          .get('/computeMetadata/v1/instance/service-accounts/?recursive=true')
          .reply(200, response);

      const body = await auth.getCredentials();
      assert(body);
      assert.equal(
          body!.client_email, 'test-creds@test-creds.iam.gserviceaccount.com');
      assert.equal(body!.private_key, null);
    });

    it('should error if metadata server is not reachable', async () => {
      const auth = new GoogleAuth();
      createIsGCENock();
      await auth._checkIsGCE();
      // Assert that the flags are set.
      assert.equal(true, auth.isGCE);

      nock('http://metadata.google.internal')
          .get('/computeMetadata/v1/instance/service-accounts/?recursive=true')
          .reply(404);

      try {
        await auth.getCredentials();
      } catch (e) {
        return;
      }
      throw new Error('Expected to throw');
    });

    it('should error if body is empty', async () => {
      const auth = new GoogleAuth();
      createIsGCENock();
      await auth._checkIsGCE();
      // Assert that the flags are set.
      assert.equal(true, auth.isGCE);

      nock('http://metadata.google.internal')
          .get('/computeMetadata/v1/instance/service-accounts/?recursive=true')
          .reply(200, {});

      try {
        await auth.getCredentials();
      } catch (e) {
        return;
      }
      throw new Error('Expected to throw');
    });

    it('should handle valid environment variable', async () => {
      // Set up a mock to return path to a valid credentials file.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(
          auth, 'GOOGLE_APPLICATION_CREDENTIALS',
          './test/fixtures/private.json');
      // Execute.
      const result =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert(result);

      const jwt = result as JWT;
      it('should return the credentials from file', async () => {
        const body = await auth.getCredentials();
        assert.notEqual(null, body);
        assert.equal(jwt.email, body!.client_email);
        assert.equal(jwt.key, body!.private_key);
      });
    });

    it('should handle valid file path', async () => {
      // Set up a mock to return path to a valid credentials file.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable(auth);
      insertEnvironmentVariableIntoAuth(auth, 'APPDATA', 'foo');
      auth._pathJoin = pathJoin;
      auth._osPlatform = () => 'win32';
      auth._fileExists = () => true;
      auth._checkIsGCE = () => Promise.resolve(true);
      insertWellKnownFilePathIntoAuth(
          auth, 'foo:gcloud:application_default_credentials.json',
          './test/fixtures/private2.json');
      // Execute.
      const result = await auth.getApplicationDefault();
      assert(result);
      const jwt = result.credential as JWT;
      it('should return the credentials from file', async () => {
        const body = await auth.getCredentials();
        assert.notEqual(null, body);
        assert.equal(jwt.email, body!.client_email);
        assert.equal(jwt.key, body!.private_key);
      });
    });

    it('should return error when env const is not set', async () => {
      // Set up a mock to return a null path string
      const auth = new GoogleAuth();
      insertEnvironmentVariableIntoAuth(auth, 'GOOGLE_APPLICATION_CREDENTIALS');
      const client =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert.equal(null, client);
      try {
        await auth.getCredentials();
      } catch (e) {
        return;
      }
      throw new Error('Expected to throw');
    });
  });
});
