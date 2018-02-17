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
import {BASE_PATH, HOST_ADDRESS} from 'gcp-metadata';
import * as http from 'http';
import * as nock from 'nock';
import * as path from 'path';
import * as stream from 'stream';

import {auth, DefaultTransporter, GoogleAuth, JWT, UserRefreshClient} from '../src/index';
import {BodyResponseCallback} from '../src/transporters';

nock.disableNetConnect();

// Cache env vars before the tests start
const envCache = process.env;

afterEach(() => {
  nock.cleanAll();
  // after each test, reset the env vars
  process.env = envCache;
});

const host = HOST_ADDRESS;
const instancePath = `${BASE_PATH}/instance`;
const svcAccountPath = `${instancePath}/service-accounts?recursive=true`;

function nockIsGCE() {
  nock(host).get(instancePath).reply(200, {}, {'metadata-flavor': 'Google'});
}

function nockNotGCE() {
  nock(host).get(instancePath).replyWithError({code: 'ETIMEDOUT'});
}

function nockENOTFOUND() {
  nock(host).get(instancePath).replyWithError({code: 'ENOTFOUND'});
}

function nockErrGCE() {
  nock(host).get(instancePath).reply(500);
}

function nock404GCE() {
  nock(host).get(instancePath).reply(404);
}

function createGetProjectIdNock(projectId: string) {
  nock(host).get(`${BASE_PATH}/project/project-id`).reply(200, projectId);
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
function blockGoogleApplicationCredentialEnvironmentVariable() {
  mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
}

// Intercepts the specified environment variable, returning the specified value.
function mockEnvVar(name: string, value?: string) {
  process.env[name] = value || '';
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
  it('should support the instantiated named export', () => {
    const result = auth.fromJSON(createJwtJSON());
    assert(result);
  });

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
          mockEnvVar('GCLOUD_PROJECT', STUB_PROJECT);
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

        describe('With eager retry', () => {
          it('should make client with eagerRetryThresholdMillis set', () => {
            const client =
                auth.fromAPIKey(API_KEY, {eagerRefreshThresholdMillis: 100});
            assert.equal(100, client.eagerRefreshThresholdMillis);
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

      it('should create JWT which eagerRefreshThresholdMillisset when this is' +
             ' set for GoogleAuth',
         () => {
           const json = createJwtJSON();
           const auth = new GoogleAuth();
           const result =
               auth.fromJSON(json, {eagerRefreshThresholdMillis: 5000});
           assert.equal(5000, (result as JWT).eagerRefreshThresholdMillis);
         });

      it('should create JWT with 5min as value for eagerRefreshThresholdMillis',
         () => {
           const json = createJwtJSON();
           const auth = new GoogleAuth();
           const result = auth.fromJSON(json);
           assert.equal(300000, (result as JWT).eagerRefreshThresholdMillis);
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


    it('should read the stream and create a jwt with eager refresh',
       async () => {
         // Read the contents of the file into a json object.
         const fileContents =
             fs.readFileSync('./test/fixtures/private.json', 'utf-8');
         const json = JSON.parse(fileContents);

         // Now open a stream on the same file.
         const stream = fs.createReadStream('./test/fixtures/private.json');

         // And pass it into the fromStream method.
         const auth = new GoogleAuth();
         const result = await auth.fromStream(
             stream, {eagerRefreshThresholdMillis: 1000 * 60 * 60});
         const jwt = result as JWT;
         // Ensure that the correct bits were pulled from the stream.
         assert.equal(json.private_key, jwt.key);
         assert.equal(json.client_email, jwt.email);
         assert.equal(null, jwt.keyFile);
         assert.equal(null, jwt.subject);
         assert.equal(null, jwt.scope);
         assert.equal(1000 * 60 * 60, jwt.eagerRefreshThresholdMillis);
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

    it('should read another stream and create a UserRefreshClient with eager refresh',
       async () => {
         // Read the contents of the file into a json object.
         const fileContents =
             fs.readFileSync('./test/fixtures/refresh.json', 'utf-8');
         const json = JSON.parse(fileContents);

         // Now open a stream on the same file.
         const stream = fs.createReadStream('./test/fixtures/refresh.json');

         // And pass it into the fromStream method.
         const auth = new GoogleAuth();
         const result =
             await auth.fromStream(stream, {eagerRefreshThresholdMillis: 100});
         // Ensure that the correct bits were pulled from the stream.
         const rc = result as UserRefreshClient;
         assert.equal(json.client_id, rc._clientId);
         assert.equal(json.client_secret, rc._clientSecret);
         assert.equal(json.refresh_token, rc._refreshToken);
         assert.equal(100, rc.eagerRefreshThresholdMillis);
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

    it('should correctly read the file and create a valid JWT with eager refresh',
       async () => {
         // Read the contents of the file into a json object.
         const fileContents =
             fs.readFileSync('./test/fixtures/private.json', 'utf-8');
         const json = JSON.parse(fileContents);

         // Now pass the same path to the auth loader.
         const auth = new GoogleAuth();
         const result = await auth._getApplicationCredentialsFromFilePath(
             './test/fixtures/private.json',
             {eagerRefreshThresholdMillis: 7000});
         assert(result);
         const jwt = result as JWT;
         assert.equal(json.private_key, jwt.key);
         assert.equal(json.client_email, jwt.email);
         assert.equal(null, jwt.keyFile);
         assert.equal(null, jwt.subject);
         assert.equal(null, jwt.scope);
         assert.equal(7000, jwt.eagerRefreshThresholdMillis);
       });
  });

  describe('._tryGetApplicationCredentialsFromEnvironmentVariable', () => {
    it('should return null when env const is not set', async () => {
      // Set up a mock to return a null path string.
      const auth = new GoogleAuth();
      mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
      const client =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert.equal(client, null);
    });

    it('should return null when env const is empty string', async () => {
      // Set up a mock to return an empty path string.
      const auth = new GoogleAuth();
      mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS', '');
      const client =
          await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
      assert.equal(client, null);
    });

    it('should handle invalid environment variable', async () => {
      // Set up a mock to return a path to an invalid file.
      const auth = new GoogleAuth();
      mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS', './nonexistantfile.json');

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
      mockEnvVar(
          'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');

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

    it('should handle valid environment variable when there is eager refresh set',
       async () => {
         // Set up a mock to return path to a valid credentials file.
         const auth = new GoogleAuth();
         mockEnvVar(
             'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');

         // Read the contents of the file into a json object.
         const fileContents =
             fs.readFileSync('./test/fixtures/private.json', 'utf-8');
         const json = JSON.parse(fileContents);

         // Execute.
         const result =
             await auth._tryGetApplicationCredentialsFromEnvironmentVariable(
                 {eagerRefreshThresholdMillis: 60 * 60 * 1000});
         const jwt = result as JWT;
         assert.equal(json.private_key, jwt.key);
         assert.equal(json.client_email, jwt.email);
         assert.equal(null, jwt.keyFile);
         assert.equal(null, jwt.subject);
         assert.equal(null, jwt.scope);
         assert.equal(60 * 60 * 1000, jwt.eagerRefreshThresholdMillis);
       });
  });

  describe('._tryGetApplicationCredentialsFromWellKnownFile', () => {
    it('should build the correct directory for Windows', async () => {
      let correctLocation = false;

      // Set up mocks.
      const auth = new GoogleAuth();
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('APPDATA', 'foo');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('HOME', 'foo');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('APPDATA');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('HOME');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('APPDATA', 'foo');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('HOME', 'foo');
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
    blockGoogleApplicationCredentialEnvironmentVariable();
    mockEnvVar('APPDATA', 'foo');
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
    blockGoogleApplicationCredentialEnvironmentVariable();
    mockEnvVar('HOME', 'foo');
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
    blockGoogleApplicationCredentialEnvironmentVariable();
    mockEnvVar('APPDATA', 'foo');
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
    blockGoogleApplicationCredentialEnvironmentVariable();
    mockEnvVar('HOME', 'foo');
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
         nockNotGCE();

         // Create a function which will set up a GoogleAuth instance to match
         // on an environment variable json file, but not on anything else.
         const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
           mockEnvVar('GCLOUD_PROJECT', fixedProjectId);
           creds._fileExists = () => false;
         };

         // Set up a new GoogleAuth and prepare it for local environment
         // variable handling.
         const auth = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth);

         // Ask for credentials, the first time.
         const projectIdPromise = auth.getDefaultProjectId();
         const projectId = await projectIdPromise;
         assert.equal(projectId, fixedProjectId);

         // Null out all the private functions that make this method work
         // tslint:disable-next-line no-any
         const anyd = (auth as any);
         anyd.getProductionProjectId = null;
         anyd.getFileProjectId = null;
         anyd.getDefaultServiceProjectId = null;
         anyd.getGCEProjectId = null;

         // Ask for projectId again, from the same auth instance. If it isn't
         // cached, this will crash.
         const projectId2 = await auth.getDefaultProjectId();

         // Make sure we get the original cached projectId back
         assert.equal(fixedProjectId, projectId2);

         // Now create a second GoogleAuth instance, and ask for projectId.
         // We should get a new projectId instance this time.
         const auth2 = new GoogleAuth();
         setUpAuthForEnvironmentVariable(auth2);

         const getProjectIdPromise = await auth2.getDefaultProjectId();
         assert.notEqual(getProjectIdPromise, projectIdPromise);
       });
  });

  it('should use GCLOUD_PROJECT environment variable when it is set',
     (done) => {
       const fixedProjectId = 'my-awesome-project';
       const auth = new GoogleAuth();
       mockEnvVar('GCLOUD_PROJECT', fixedProjectId);
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
       mockEnvVar('GOOGLE_CLOUD_PROJECT', fixedProjectId);

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
       mockEnvVar(
           'GOOGLE_APPLICATION_CREDENTIALS',
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
       blockGoogleApplicationCredentialEnvironmentVariable();
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
       blockGoogleApplicationCredentialEnvironmentVariable();
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
       nockNotGCE();
       // Create a function which will set up a GoogleAuth instance to match
       // on an environment variable json file, but not on anything else.
       const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
         mockEnvVar(
             'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');

         creds._fileExists = () => false;
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
    mockEnvVar(
        'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
    mockEnvVar('APPDATA', 'foo');
    auth._pathJoin = pathJoin;
    auth._osPlatform = () => 'win32';
    auth._fileExists = () => true;
    nockIsGCE();
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
       blockGoogleApplicationCredentialEnvironmentVariable();
       mockEnvVar('APPDATA', 'foo');
       auth._pathJoin = pathJoin;
       auth._osPlatform = () => 'win32';
       auth._fileExists = () => true;
       nockIsGCE();
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
       blockGoogleApplicationCredentialEnvironmentVariable();
       mockEnvVar('APPDATA', 'foo');
       auth._pathJoin = pathJoin;
       auth._osPlatform = () => 'win32';
       auth._fileExists = () => false;
       nockIsGCE();

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
    blockGoogleApplicationCredentialEnvironmentVariable();
    mockEnvVar('APPDATA', 'foo');
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
    mockEnvVar(
        'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
    mockEnvVar('GCLOUD_PROJECT', testProjectId);
    mockEnvVar('APPDATA', 'foo');
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
    assert.notEqual(true, auth.isGCE);
    nockIsGCE();
    const isGCE = await auth._checkIsGCE();
    assert.equal(true, auth.isGCE);
  });

  it('should not set the _isGCE flag when not running on GCE', async () => {
    const auth = new GoogleAuth();
    nockNotGCE();
    assert.notEqual(true, auth.isGCE);
    const isGCE = await auth._checkIsGCE();
    assert.equal(false, auth.isGCE);
  });

  it('should retry the check for isGCE if it fails the first time',
     async () => {
       const auth = new GoogleAuth();
       assert.notEqual(true, auth.isGCE);
       // the first request will fail
       nockErrGCE();
       // the second one will succeed
       nockIsGCE();
       const isGCE = await auth._checkIsGCE();
       assert.equal(true, auth.isGCE);
     });

  it('should not retry the check for isGCE if it fails with a 404',
     async () => {
       const auth = new GoogleAuth();
       assert.notEqual(true, auth.isGCE);
       nock404GCE();
       const isGCE = await auth._checkIsGCE();
       assert.notEqual(true, auth.isGCE);
     });

  it('should not retry the check for isGCE if it fails with an ENOTFOUND',
     async () => {
       const auth = new GoogleAuth();
       assert.notEqual(true, auth.isGCE);
       nockENOTFOUND();
       const isGCE = await auth._checkIsGCE();
       assert.notEqual(true, auth.isGCE);
     });

  it('Does not execute the second time when running on GCE', async () => {
    // This test relies on the nock mock only getting called once.
    const auth = new GoogleAuth();
    assert.notEqual(true, auth.isGCE);
    nockIsGCE();
    await auth._checkIsGCE();
    assert.equal(true, auth.isGCE);
    const isGCE2 = await auth._checkIsGCE();
    assert.equal(true, auth.isGCE);
  });

  it('Does not execute the second time when not running on GCE', async () => {
    const auth = new GoogleAuth();
    assert.notEqual(true, auth.isGCE);
    nockNotGCE();
    await auth._checkIsGCE();
    assert.equal(false, auth.isGCE);
    await auth._checkIsGCE();
    assert.equal(false, auth.isGCE);

    it('Returns false on transport error', async () => {
      const auth2 = new GoogleAuth();
      assert.notEqual(true, auth2.isGCE);
      nockErrGCE();
      await auth2._checkIsGCE();
      assert.equal(false, auth2.isGCE);
    });
  });

  describe('.getCredentials', () => {
    it('should get metadata from the server when running on GCE', async () => {
      const auth = new GoogleAuth();
      nockIsGCE();
      const isGCE = await auth._checkIsGCE();
      assert.equal(true, auth.isGCE);

      const response = {
        default: {
          email: 'test-creds@test-creds.iam.gserviceaccount.com',
          private_key: null
        }
      };
      nock.cleanAll();
      nock(host).get(svcAccountPath).reply(200, response, {
        'Metadata-Flavor': 'Google'
      });
      const body = await auth.getCredentials();
      assert(body);
      assert.equal(
          body!.client_email, 'test-creds@test-creds.iam.gserviceaccount.com');
      assert.equal(body!.private_key, null);
    });

    it('should error if metadata server is not reachable', async () => {
      const auth = new GoogleAuth();
      nockIsGCE();
      await auth._checkIsGCE();
      assert.equal(true, auth.isGCE);
      nock(HOST_ADDRESS).get(svcAccountPath).reply(404);
      try {
        await auth.getCredentials();
      } catch (e) {
        return;
      }
      throw new Error('Expected to throw');
    });

    it('should error if body is empty', async () => {
      const auth = new GoogleAuth();
      nockIsGCE();
      await auth._checkIsGCE();
      assert.equal(true, auth.isGCE);
      nock(HOST_ADDRESS).get(svcAccountPath).reply(200, {});

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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar(
          'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
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
      blockGoogleApplicationCredentialEnvironmentVariable();
      mockEnvVar('APPDATA', 'foo');
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
      mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
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

    it('should use jsonContent if available', async () => {
      const json = createJwtJSON();
      const auth = new GoogleAuth();
      const result = auth.fromJSON(json);
      // We know this returned a cached result if a nock scope isn't required
      const body = await auth.getCredentials();
      assert.notEqual(body, null);
      assert.equal(body!.client_email, 'hello@youarecool.com');
    });
  });
});
