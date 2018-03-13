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
import * as child_process from 'child_process';
import * as fs from 'fs';
import {BASE_PATH, HEADERS, HOST_ADDRESS} from 'gcp-metadata';
import * as nock from 'nock';
import * as path from 'path';
import * as sinon from 'sinon';
import * as stream from 'stream';

import * as envDetect from '../src/auth/envDetect';
import {GoogleAuth, JWT, UserRefreshClient} from '../src/index';

nock.disableNetConnect();

const tokenPath = `${BASE_PATH}/instance/service-accounts/default/token`;
const host = HOST_ADDRESS;
const instancePath = `${BASE_PATH}/instance`;
const svcAccountPath = `${instancePath}/service-accounts?recursive=true`;
const API_KEY = 'test-123';
const STUB_PROJECT = 'my-awesome-project';
const ENDPOINT = '/events:report';
const RESPONSE_BODY = 'RESPONSE_BODY';
const BASE_URL = [
  'https://clouderrorreporting.googleapis.com/v1beta1/projects', STUB_PROJECT
].join('/');

const privateJSON = require('../../test/fixtures/private.json');
const private2JSON = require('../../test/fixtures/private2.json');
const refreshJSON = require('../../test/fixtures/refresh.json');
const fixedProjectId = 'my-awesome-project';

let auth: GoogleAuth;
let sandbox: sinon.SinonSandbox|undefined;
beforeEach(() => {
  auth = new GoogleAuth();
});

afterEach(() => {
  nock.cleanAll();
  // after each test, reset the env vars
  if (sandbox) {
    sandbox.restore();
    sandbox = undefined;
  }
});

function nockIsGCE() {
  return nock(host).get(instancePath).reply(200, {}, HEADERS);
}

function nockNotGCE() {
  return nock(host).get(instancePath).replyWithError({code: 'ETIMEDOUT'});
}

function nockENOTFOUND() {
  return nock(host).get(instancePath).replyWithError({code: 'ENOTFOUND'});
}

function nockErrGCE() {
  return nock(host).get(instancePath).reply(500);
}

function nock404GCE() {
  return nock(host).get(instancePath).reply(404);
}

function createGetProjectIdNock(projectId: string) {
  return nock(host)
      .get(`${BASE_PATH}/project/project-id`)
      .reply(200, projectId, HEADERS);
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

// Pretend that we're GCE, and mock an access token.
function mockGCE() {
  const scope1 = nockIsGCE();
  blockGoogleApplicationCredentialEnvironmentVariable();
  const auth = new GoogleAuth();
  auth._fileExists = () => false;
  const scope2 =
      nock(HOST_ADDRESS)
          .get(tokenPath)
          .reply(200, {access_token: 'abc123', expires_in: 10000}, HEADERS);
  return {auth, scopes: [scope1, scope2]};
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
  return mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
}

// Intercepts the specified environment variable, returning the specified value.
function mockEnvVar(name: string, value = '') {
  if (!sandbox) {
    sandbox = sinon.createSandbox();
  }
  const envVars = Object.assign({}, process.env, {[name]: value});
  const stub = sandbox.stub(process, 'env').value(envVars);
  return stub;
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

it('fromJSON should support the instantiated named export', () => {
  const result = auth.fromJSON(createJwtJSON());
  assert(result);
});

it('fromJson should error on null json', () => {
  const auth = new GoogleAuth();
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (auth as any).fromJSON(null);
  });
});


it('fromAPIKey should error given an invalid api key', () => {
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (auth as any).fromAPIKey(null);
  });
});

it('should make a request with the api key', async () => {
  const scope =
      nock(BASE_URL).post(ENDPOINT).query({key: API_KEY}).reply(uri => {
        assert(uri.indexOf('key=' + API_KEY) > -1);
        return [200, RESPONSE_BODY];
      });
  const client = auth.fromAPIKey(API_KEY);
  const res = await client.request(
      {url: BASE_URL + ENDPOINT, method: 'POST', data: {'test': true}});
  assert.strictEqual(RESPONSE_BODY, res.data);
  scope.done();
});

it('should make a request while preserving original parameters', async () => {
  const OTHER_QS_PARAM = {test: 'abc'};
  const scope = nock(BASE_URL)
                    .post(ENDPOINT)
                    .query({test: OTHER_QS_PARAM.test, key: API_KEY})
                    .reply(uri => {
                      assert(uri.indexOf('key=' + API_KEY) > -1);
                      assert(uri.indexOf('test=' + OTHER_QS_PARAM.test) > -1);
                      return [200, RESPONSE_BODY];
                    });
  const client = auth.fromAPIKey(API_KEY);
  const res = await client.request({
    url: BASE_URL + ENDPOINT,
    method: 'POST',
    data: {'test': true},
    params: OTHER_QS_PARAM
  });
  assert.strictEqual(RESPONSE_BODY, res.data);
  scope.done();
});

it('should make client with eagerRetryThresholdMillis set', () => {
  const client = auth.fromAPIKey(API_KEY, {eagerRefreshThresholdMillis: 100});
  assert.equal(100, client.eagerRefreshThresholdMillis);
});

it('fromJSON should error on empty json', () => {
  const auth = new GoogleAuth();
  assert.throws(() => {
    auth.fromJSON({});
  });
});

it('fromJSON should error on missing client_email', () => {
  const json = createJwtJSON();
  delete json.client_email;
  assert.throws(() => {
    auth.fromJSON(json);
  });
});

it('fromJSON should error on missing private_key', () => {
  const json = createJwtJSON();
  delete json.private_key;
  assert.throws(() => {
    auth.fromJSON(json);
  });
});

it('fromJSON should create JWT with client_email', () => {
  const json = createJwtJSON();
  const result = auth.fromJSON(json);
  assert.equal(json.client_email, (result as JWT).email);
});

it('fromJSON should create JWT with private_key', () => {
  const json = createJwtJSON();
  const result = auth.fromJSON(json);
  assert.equal(json.private_key, (result as JWT).key);
});

it('fromJSON should create JWT with null scopes', () => {
  const json = createJwtJSON();
  const result = auth.fromJSON(json);
  assert.equal(null, (result as JWT).scopes);
});

it('fromJSON should create JWT with null subject', () => {
  const json = createJwtJSON();
  const result = auth.fromJSON(json);
  assert.equal(null, (result as JWT).subject);
});

it('fromJSON should create JWT with null keyFile', () => {
  const json = createJwtJSON();
  const result = auth.fromJSON(json);
  assert.equal(null, (result as JWT).keyFile);
});

it('fromJSON should create JWT which eagerRefreshThresholdMillisset when this is set for GoogleAuth',
   () => {
     const json = createJwtJSON();
     const result = auth.fromJSON(json, {eagerRefreshThresholdMillis: 5000});
     assert.equal(5000, (result as JWT).eagerRefreshThresholdMillis);
   });

it('fromJSON should create JWT with 5min as value for eagerRefreshThresholdMillis',
   () => {
     const json = createJwtJSON();
     const result = auth.fromJSON(json);
     assert.equal(300000, (result as JWT).eagerRefreshThresholdMillis);
   });

it('fromStream should error on null stream', (done) => {
  // Test verifies invalid parameter tests, which requires cast to any.
  // tslint:disable-next-line no-any
  (auth as any).fromStream(null, (err: Error) => {
    assert.equal(true, err instanceof Error);
    done();
  });
});

it('fromStream should read the stream and create a jwt', async () => {
  const stream = fs.createReadStream('./test/fixtures/private.json');
  // And pass it into the fromStream method.
  const res = await auth.fromStream(stream);
  const jwt = res as JWT;
  // Ensure that the correct bits were pulled from the stream.
  assert.equal(privateJSON.private_key, jwt.key);
  assert.equal(privateJSON.client_email, jwt.email);
  assert.equal(null, jwt.keyFile);
  assert.equal(null, jwt.subject);
  assert.equal(null, jwt.scope);
});

it('fromStream should read the stream and create a jwt with eager refresh',
   async () => {
     const stream = fs.createReadStream('./test/fixtures/private.json');
     const auth = new GoogleAuth();
     const result = await auth.fromStream(
         stream, {eagerRefreshThresholdMillis: 1000 * 60 * 60});
     const jwt = result as JWT;
     // Ensure that the correct bits were pulled from the stream.
     assert.equal(privateJSON.private_key, jwt.key);
     assert.equal(privateJSON.client_email, jwt.email);
     assert.equal(null, jwt.keyFile);
     assert.equal(null, jwt.subject);
     assert.equal(null, jwt.scope);
     assert.equal(1000 * 60 * 60, jwt.eagerRefreshThresholdMillis);
   });

it('should read another stream and create a UserRefreshClient', async () => {
  const stream = fs.createReadStream('./test/fixtures/refresh.json');
  const auth = new GoogleAuth();
  const res = await auth.fromStream(stream);
  // Ensure that the correct bits were pulled from the stream.
  const rc = res as UserRefreshClient;
  assert.equal(refreshJSON.client_id, rc._clientId);
  assert.equal(refreshJSON.client_secret, rc._clientSecret);
  assert.equal(refreshJSON.refresh_token, rc._refreshToken);
});

it('should read another stream and create a UserRefreshClient with eager refresh',
   async () => {
     const stream = fs.createReadStream('./test/fixtures/refresh.json');
     const auth = new GoogleAuth();
     const result =
         await auth.fromStream(stream, {eagerRefreshThresholdMillis: 100});
     // Ensure that the correct bits were pulled from the stream.
     const rc = result as UserRefreshClient;
     assert.equal(refreshJSON.client_id, rc._clientId);
     assert.equal(refreshJSON.client_secret, rc._clientSecret);
     assert.equal(refreshJSON.refresh_token, rc._refreshToken);
     assert.equal(100, rc.eagerRefreshThresholdMillis);
   });

it('getApplicationCredentialsFromFilePath should not error on valid symlink',
   async () => {
     await auth._getApplicationCredentialsFromFilePath(
         './test/fixtures/goodlink');
   });

it('getApplicationCredentialsFromFilePath should error on invalid symlink',
   async () => {
     try {
       await auth._getApplicationCredentialsFromFilePath(
           './test/fixtures/badlink');
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on valid link to invalid data',
   async () => {
     try {
       await auth._getApplicationCredentialsFromFilePath(
           './test/fixtures/emptylink');
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on null file path',
   async () => {
     try {
       // Test verifies invalid parameter tests, which requires cast to any.
       // tslint:disable-next-line no-any
       await (auth as any)._getApplicationCredentialsFromFilePath(null);
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on empty file path',
   async () => {
     try {
       await auth._getApplicationCredentialsFromFilePath('');
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on non-string file path',
   async () => {
     try {
       // Test verifies invalid parameter tests, which requires cast to any.
       // tslint:disable-next-line no-any
       await auth._getApplicationCredentialsFromFilePath(2 as any);
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on invalid file path',
   async () => {
     try {
       await auth._getApplicationCredentialsFromFilePath(
           './nonexistantfile.json');
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should error on directory',
   async () => {
     // Make sure that the following path actually does point to a directory.
     const directory = './test/fixtures';
     assert.equal(true, fs.lstatSync(directory).isDirectory());
     try {
       await auth._getApplicationCredentialsFromFilePath(directory);
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('getApplicationCredentialsFromFilePath should handle errors thrown from createReadStream',
   async () => {
     // Set up a mock to throw from the createReadStream method.
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

it('getApplicationCredentialsFromFilePath should handle errors thrown from fromStream',
   async () => {
     // Set up a mock to throw from the fromStream method.
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

it('getApplicationCredentialsFromFilePath should handle errors passed from fromStream',
   async () => {
     // Set up a mock to return an error from the fromStream method.
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

it('getApplicationCredentialsFromFilePath should correctly read the file and create a valid JWT',
   async () => {
     const result = await auth._getApplicationCredentialsFromFilePath(
         './test/fixtures/private.json');
     assert(result);
     const jwt = result as JWT;
     assert.equal(privateJSON.private_key, jwt.key);
     assert.equal(privateJSON.client_email, jwt.email);
     assert.equal(null, jwt.keyFile);
     assert.equal(null, jwt.subject);
     assert.equal(null, jwt.scope);
   });

it('getApplicationCredentialsFromFilePath should correctly read the file and create a valid JWT with eager refresh',
   async () => {
     const result = await auth._getApplicationCredentialsFromFilePath(
         './test/fixtures/private.json', {eagerRefreshThresholdMillis: 7000});
     assert(result);
     const jwt = result as JWT;
     assert.equal(privateJSON.private_key, jwt.key);
     assert.equal(privateJSON.client_email, jwt.email);
     assert.equal(null, jwt.keyFile);
     assert.equal(null, jwt.subject);
     assert.equal(null, jwt.scope);
     assert.equal(7000, jwt.eagerRefreshThresholdMillis);
   });

it('tryGetApplicationCredentialsFromEnvironmentVariable should return null when env const is not set',
   async () => {
     // Set up a mock to return a null path string.
     mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
     const client =
         await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
     assert.equal(client, null);
   });

it('tryGetApplicationCredentialsFromEnvironmentVariable should return null when env const is empty string',
   async () => {
     // Set up a mock to return an empty path string.
     const stub = mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS');
     const client =
         await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
     assert.equal(client, null);
   });

it('tryGetApplicationCredentialsFromEnvironmentVariable should handle invalid environment variable',
   async () => {
     // Set up a mock to return a path to an invalid file.
     mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS', './nonexistantfile.json');
     try {
       await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
     } catch (e) {
       return;
     }
     assert.fail('failed to throw');
   });

it('tryGetApplicationCredentialsFromEnvironmentVariable should handle valid environment variable',
   async () => {
     // Set up a mock to return path to a valid credentials file.
     mockEnvVar(
         'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
     const result =
         await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
     const jwt = result as JWT;
     assert.equal(privateJSON.private_key, jwt.key);
     assert.equal(privateJSON.client_email, jwt.email);
     assert.equal(null, jwt.keyFile);
     assert.equal(null, jwt.subject);
     assert.equal(null, jwt.scope);
   });

it('tryGetApplicationCredentialsFromEnvironmentVariable should handle valid environment variable when there is eager refresh set',
   async () => {
     // Set up a mock to return path to a valid credentials file.
     mockEnvVar(
         'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
     const result =
         await auth._tryGetApplicationCredentialsFromEnvironmentVariable(
             {eagerRefreshThresholdMillis: 60 * 60 * 1000});
     const jwt = result as JWT;
     assert.equal(privateJSON.private_key, jwt.key);
     assert.equal(privateJSON.client_email, jwt.email);
     assert.equal(null, jwt.keyFile);
     assert.equal(null, jwt.subject);
     assert.equal(null, jwt.scope);
     assert.equal(60 * 60 * 1000, jwt.eagerRefreshThresholdMillis);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should build the correct directory for Windows',
   async () => {
     let correctLocation = false;
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
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert(result);
     assert(correctLocation);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should build the correct directory for non-Windows',
   () => {
     let correctLocation = false;
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
     const client = auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert(client);
     assert(correctLocation);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should fail on Windows when APPDATA is not defined',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath =
         (filePath: string): Promise<JWT|UserRefreshClient> => {
           return Promise.resolve({} as JWT);
         };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal(null, result);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should fail on non-Windows when HOME is not defined',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('HOME');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'linux';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath =
         (filePath: string): Promise<JWT|UserRefreshClient> => {
           return Promise.resolve({} as JWT);
         };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal(null, result);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should fail on Windows when file does not exist',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => false;
     auth._getApplicationCredentialsFromFilePath =
         (filePath: string): Promise<JWT|UserRefreshClient> => {
           return Promise.resolve({} as JWT);
         };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal(null, result);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should fail on non-Windows when file does not exist',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('HOME', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'linux';
     auth._fileExists = () => false;
     auth._getApplicationCredentialsFromFilePath =
         (filePath: string): Promise<JWT|UserRefreshClient> => {
           return Promise.resolve({} as JWT);
         };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal(null, result);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should succeeds on Windows',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
       return Promise.resolve(new JWT('hello'));
     };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal('hello', (result as JWT)!.email);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should succeeds on non-Windows',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('HOME', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'linux';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
       return Promise.resolve(new JWT('hello'));
     };
     const result = await auth._tryGetApplicationCredentialsFromWellKnownFile();
     assert.equal('hello', (result as JWT).email);
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should pass along a failure on Windows',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
       throw new Error('hello');
     };
     try {
       await auth._tryGetApplicationCredentialsFromWellKnownFile();
     } catch (e) {
       assert(e);
       assert.equal('hello', e.message);
       return;
     }
     assert.fail('failed to throw');
   });

it('_tryGetApplicationCredentialsFromWellKnownFile should pass along a failure on non-Windows',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('HOME', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'linux';
     auth._fileExists = () => true;
     auth._getApplicationCredentialsFromFilePath = (filePath: string) => {
       throw new Error('hello');
     };
     try {
       await auth._tryGetApplicationCredentialsFromWellKnownFile();
     } catch (e) {
       assert.equal('hello', e.message);
       return;
     }
     assert.fail('failed to throw');
   });

it('getDefaultProjectId should return a new projectId the first time and a cached projectId the second time',
   async () => {
     // Create a function which will set up a GoogleAuth instance to match
     // on an environment variable json file, but not on anything else.
     const setUpAuthForEnvironmentVariable = (creds: GoogleAuth) => {
       mockEnvVar('GCLOUD_PROJECT', fixedProjectId);
       creds._fileExists = () => false;
     };

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

     const getProjectIdPromise = auth2.getDefaultProjectId();
     assert.notEqual(getProjectIdPromise, projectIdPromise);
   });

it('getDefaultProjectId should use GCLOUD_PROJECT environment variable when it is set',
   async () => {
     mockEnvVar('GCLOUD_PROJECT', fixedProjectId);
     const projectId = await auth.getDefaultProjectId();
     assert.equal(projectId, fixedProjectId);
   });

it('getDefaultProjectId should use GOOGLE_CLOUD_PROJECT environment variable when it is set',
   async () => {
     mockEnvVar('GOOGLE_CLOUD_PROJECT', fixedProjectId);
     const projectId = await auth.getDefaultProjectId();
     assert.equal(projectId, fixedProjectId);
   });

it('getDefaultProjectId should use GOOGLE_APPLICATION_CREDENTIALS file when it is available',
   async () => {
     mockEnvVar(
         'GOOGLE_APPLICATION_CREDENTIALS',
         path.join(__dirname, '../../test/fixtures/private2.json'));
     const projectId = await auth.getDefaultProjectId();
     assert.equal(projectId, fixedProjectId);
   });

it('getDefaultProjectId should use Cloud SDK when it is available and env vars are not set',
   async () => {
     // Set up the creds.
     // * Environment variable is not set.
     // * Well-known file is set up to point to private2.json
     // * Running on GCE is set to true.
     sandbox = sinon.createSandbox();
     blockGoogleApplicationCredentialEnvironmentVariable();
     const stdout = JSON.stringify(
         {configuration: {properties: {core: {project: fixedProjectId}}}});
     const stub = sandbox.stub(child_process, 'exec')
                      .callsArgWith(1, null, stdout, null);
     const projectId = await auth.getDefaultProjectId();
     assert(stub.calledOnce);
     assert.equal(projectId, fixedProjectId);
   });


it('getDefaultProjectId should use GCE when well-known file and env const are not set',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     sandbox = sinon.createSandbox();
     const stub =
         sandbox.stub(child_process, 'exec').callsArgWith(1, null, '', null);
     const scope = createGetProjectIdNock(fixedProjectId);
     const projectId = await auth.getDefaultProjectId();
     assert(stub.calledOnce);
     assert.equal(projectId, fixedProjectId);
     scope.done();
   });

it('getApplicationDefault should return a new credential the first time and a cached credential the second time',
   async () => {
     const scope = nockNotGCE();
     // Create a function which will set up a GoogleAuth instance to match
     // on an environment variable json file, but not on anything else.
     mockEnvVar(
         'GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
     auth._fileExists = () => false;

     // Ask for credentials, the first time.
     const result = await auth.getApplicationDefault();
     assert.notEqual(null, result);

     // Capture the returned credential.
     const cachedClient = result.client;

     // Make sure our special test bit is not set yet, indicating that
     // this is a new credentials instance.
     // Test verifies invalid parameter tests, which requires cast to any.
     // tslint:disable-next-line no-any
     assert.equal(null, (cachedClient as any).specialTestBit);

     // Now set the special test bit.
     // Test verifies invalid parameter tests, which requires cast to any.
     // tslint:disable-next-line no-any
     (cachedClient as any).specialTestBit = 'monkey';

     // Ask for credentials again, from the same auth instance. We expect
     // a cached instance this time.
     const result2 = (await auth.getApplicationDefault()).client;
     assert.notEqual(null, result2);

     // Make sure the special test bit is set on the credentials we got
     // back, indicating that we got cached credentials. Also make sure
     // the object instance is the same.
     // Test verifies invalid parameter tests, which requires cast to
     // any.
     // tslint:disable-next-line no-any
     assert.equal('monkey', (result2 as any).specialTestBit);
     assert.equal(cachedClient, result2);

     // Now create a second GoogleAuth instance, and ask for
     // credentials. We should get a new credentials instance this time.
     const auth2 = new GoogleAuth();
     auth2._fileExists = () => false;

     const result3 = (await auth2.getApplicationDefault()).client;
     assert.notEqual(null, result3);

     // Make sure we get a new (non-cached) credential instance back.
     // Test verifies invalid parameter tests, which requires cast to
     // any.
     // tslint:disable-next-line no-any
     assert.equal(null, (result3 as any).specialTestBit);
     assert.notEqual(cachedClient, result3);
   });

it('getApplicationDefault should cache the credential when using GCE',
   async () => {
     blockGoogleApplicationCredentialEnvironmentVariable();
     auth._fileExists = () => false;
     const scope = nockIsGCE();

     // Ask for credentials, the first time.
     const result = await auth.getApplicationDefault();
     scope.done();
     assert.notEqual(null, result);

     // Capture the returned credential.
     const cachedCredential = result.client;

     // Ask for credentials again, from the same auth instance. We expect
     // a cached instance this time.
     const result2 = (await auth.getApplicationDefault()).client;
     assert.notEqual(null, result2);

     // Make sure it's the same object
     assert.equal(cachedCredential, result2);
   });

it('getApplicationDefault should use environment variable when it is set',
   async () => {
     // Set up the creds.
     // * Environment variable is set up to point to private.json
     // * Well-known file is set up to point to private2.json
     // * Running on GCE is set to true.
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

     const res = await auth.getApplicationDefault();
     const client = res.client as JWT;
     assert.equal(privateJSON.private_key, client.key);
     assert.equal(privateJSON.client_email, client.email);
     assert.equal(null, client.keyFile);
     assert.equal(null, client.subject);
     assert.equal(null, client.scope);
   });

it('should use well-known file when it is available and env const is not set',
   async () => {
     // Set up the creds.
     // * Environment variable is not set.
     // * Well-known file is set up to point to private2.json
     // * Running on GCE is set to true.
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => true;
     nockIsGCE();
     insertWellKnownFilePathIntoAuth(
         auth, 'foo:gcloud:application_default_credentials.json',
         './test/fixtures/private2.json');

     const res = await auth.getApplicationDefault();
     const client = res.client as JWT;
     assert.equal(private2JSON.private_key, client.key);
     assert.equal(private2JSON.client_email, client.email);
     assert.equal(null, client.keyFile);
     assert.equal(null, client.subject);
     assert.equal(null, client.scope);
   });

it('getApplicationDefault should use GCE when well-known file and env const are not set',
   async () => {
     // Set up the creds.
     // * Environment variable is not set.
     // * Well-known file is not set.
     // * Running on GCE is set to true.
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => false;
     const scope = nockIsGCE();
     const res = await auth.getApplicationDefault();
     scope.done();
     // This indicates that we got a ComputeClient instance back, rather than a
     // JWTClient.
     assert.equal('compute-placeholder', res.client.credentials.refresh_token);
   });


it('getApplicationDefault should report GCE error when checking for GCE fails',
   async () => {
     // Set up the creds.
     // * Environment variable is not set.
     // * Well-known file is not set.
     // * Running on GCE is set to true.
     blockGoogleApplicationCredentialEnvironmentVariable();
     mockEnvVar('APPDATA', 'foo');
     auth._pathJoin = pathJoin;
     auth._osPlatform = () => 'win32';
     auth._fileExists = () => false;
     auth._checkIsGCE = () => {
       throw new Error('fake error');
     };
     try {
       await auth.getApplicationDefault();
     } catch (e) {
       return;
     }
     throw new Error('Expected to throw');
   });

it('getApplicationDefault should also get project ID', async () => {
  // Set up the creds.
  // * Environment variable is set up to point to private.json
  // * Well-known file is set up to point to private2.json
  // * Running on GCE is set to true.
  mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
  mockEnvVar('GCLOUD_PROJECT', fixedProjectId);
  mockEnvVar('APPDATA', 'foo');
  auth._pathJoin = pathJoin;
  auth._osPlatform = () => 'win32';
  auth._fileExists = () => true;
  auth._checkIsGCE = () => Promise.resolve(true);
  insertWellKnownFilePathIntoAuth(
      auth, 'foo:gcloud:application_default_credentials.json',
      './test/fixtures/private2.json');

  const res = await auth.getApplicationDefault();
  const client = res.client as JWT;
  assert.equal(privateJSON.private_key, client.key);
  assert.equal(privateJSON.client_email, client.email);
  assert.equal(res.projectId, fixedProjectId);
  assert.equal(null, client.keyFile);
  assert.equal(null, client.subject);
  assert.equal(null, client.scope);
});

it('_checkIsGCE should set the _isGCE flag when running on GCE', async () => {
  assert.notEqual(true, auth.isGCE);
  const scope = nockIsGCE();
  const isGCE = await auth._checkIsGCE();
  assert.equal(true, auth.isGCE);
  scope.done();
});

it('_checkIsGCE should not set the _isGCE flag when not running on GCE',
   async () => {
     const scope = nockNotGCE();
     assert.notEqual(true, auth.isGCE);
     const isGCE = await auth._checkIsGCE();
     assert.equal(false, auth.isGCE);
     scope.done();
   });

it('_checkIsGCE should retry the check for isGCE if it fails the first time',
   async () => {
     assert.notEqual(true, auth.isGCE);
     // the first request will fail, the second one will succeed
     const scopes = [nockErrGCE(), nockIsGCE()];
     const isGCE = await auth._checkIsGCE();
     assert.equal(true, auth.isGCE);
     scopes.forEach(s => s.done());
   });

it('should not retry the check for isGCE if it fails with a 404', async () => {
  assert.notEqual(true, auth.isGCE);
  const scope = nock404GCE();
  const isGCE = await auth._checkIsGCE();
  assert.notEqual(true, auth.isGCE);
  scope.done();
});

it('_checkIsGCE should not retry the check for isGCE if it fails with an ENOTFOUND',
   async () => {
     assert.notEqual(true, auth.isGCE);
     const scope = nockENOTFOUND();
     const isGCE = await auth._checkIsGCE();
     assert.notEqual(true, auth.isGCE);
     scope.done();
   });

it('_checkIsGCE does not execute the second time when running on GCE',
   async () => {
     // This test relies on the nock mock only getting called once.
     assert.notEqual(true, auth.isGCE);
     const scope = nockIsGCE();
     await auth._checkIsGCE();
     assert.equal(true, auth.isGCE);
     const isGCE2 = await auth._checkIsGCE();
     assert.equal(true, auth.isGCE);
     scope.done();
   });

it('_checkIsGCE does not execute the second time when not running on GCE',
   async () => {
     assert.notEqual(true, auth.isGCE);
     const scope = nockNotGCE();
     await auth._checkIsGCE();
     assert.equal(false, auth.isGCE);
     await auth._checkIsGCE();
     assert.equal(false, auth.isGCE);
     scope.done();
   });

it('_checkIsGCE returns false on transport error', async () => {
  assert.notEqual(true, auth.isGCE);
  const scope = nockErrGCE();
  await auth._checkIsGCE();
  assert.equal(false, auth.isGCE);
  scope.done();
});

it('getCredentials should get metadata from the server when running on GCE',
   async () => {
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
     const scope = nock(host).get(svcAccountPath).reply(200, response, HEADERS);
     const body = await auth.getCredentials();
     assert(body);
     assert.equal(
         body!.client_email, 'test-creds@test-creds.iam.gserviceaccount.com');
     assert.equal(body!.private_key, null);
     scope.done();
   });

it('getCredentials should error if metadata server is not reachable',
   async () => {
     const scopes =
         [nockIsGCE(), nock(HOST_ADDRESS).get(svcAccountPath).reply(404)];
     await auth._checkIsGCE();
     assert.equal(true, auth.isGCE);
     try {
       await auth.getCredentials();
     } catch (e) {
       scopes.forEach(s => s.done());
       return;
     }
     throw new Error('Expected to throw');
   });

it('getCredentials should error if body is empty', async () => {
  const scopes =
      [nockIsGCE(), nock(HOST_ADDRESS).get(svcAccountPath).reply(200, {})];
  await auth._checkIsGCE();
  assert.equal(true, auth.isGCE);
  try {
    await auth.getCredentials();
  } catch (e) {
    scopes.forEach(s => s.done());
    return;
  }
  throw new Error('Expected to throw');
});

it('getCredentials should handle valid environment variable', async () => {
  // Set up a mock to return path to a valid credentials file.
  blockGoogleApplicationCredentialEnvironmentVariable();
  mockEnvVar('GOOGLE_APPLICATION_CREDENTIALS', './test/fixtures/private.json');
  const result =
      await auth._tryGetApplicationCredentialsFromEnvironmentVariable();
  assert(result);
  const jwt = result as JWT;
  const body = await auth.getCredentials();
  assert.notEqual(null, body);
  assert.equal(jwt.email, body!.client_email);
  assert.equal(jwt.key, body!.private_key);
});

it('getCredentials should handle valid file path', async () => {
  // Set up a mock to return path to a valid credentials file.
  blockGoogleApplicationCredentialEnvironmentVariable();
  mockEnvVar('APPDATA', 'foo');
  auth._pathJoin = pathJoin;
  auth._osPlatform = () => 'win32';
  auth._fileExists = () => true;
  auth._checkIsGCE = () => Promise.resolve(true);
  insertWellKnownFilePathIntoAuth(
      auth, 'foo:gcloud:application_default_credentials.json',
      './test/fixtures/private2.json');
  const result = await auth.getApplicationDefault();
  assert(result);
  const jwt = result.client as JWT;
  const body = await auth.getCredentials();
  assert.notEqual(null, body);
  assert.equal(jwt.email, body!.client_email);
  assert.equal(jwt.key, body!.private_key);
});

it('getCredentials should return error when env const is not set', async () => {
  // Set up a mock to return a null path string
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
  const result = auth.fromJSON(json);
  // We know this returned a cached result if a nock scope isn't required
  const body = await auth.getCredentials();
  assert.notEqual(body, null);
  assert.equal(body!.client_email, 'hello@youarecool.com');
});

it('should accept keyFilename to get a client', async () => {
  const auth = new GoogleAuth({keyFilename: './test/fixtures/private.json'});
  const client = await auth.getClient() as JWT;
  assert.equal(client.email, 'hello@youarecool.com');
});

it('should accept credentials to get a client', async () => {
  const credentials = require('../../test/fixtures/private.json');
  const auth = new GoogleAuth({credentials});
  const client = await auth.getClient() as JWT;
  assert.equal(client.email, 'hello@youarecool.com');
});

it('should allow passing scopes to get a client', async () => {
  const scopes = ['http://examples.com/is/a/scope'];
  const keyFilename = './test/fixtures/private.json';
  const client = await auth.getClient({scopes, keyFilename}) as JWT;
  assert.equal(client.scopes, scopes);
});

it('should allow passing a scope to get a client', async () => {
  const scopes = 'http://examples.com/is/a/scope';
  const keyFilename = './test/fixtures/private.json';
  const client = await auth.getClient({scopes, keyFilename}) as JWT;
  assert.equal(client.scopes, scopes);
});

it('should get an access token', async () => {
  const {auth, scopes} = mockGCE();
  const token = await auth.getAccessToken();
  scopes.forEach(s => s.done());
  assert.equal(token, 'abc123');
});

it('should get request headers', async () => {
  const {auth, scopes} = mockGCE();
  const headers = await auth.getRequestHeaders();
  scopes.forEach(s => s.done());
  assert.deepEqual(headers, {Authorization: 'Bearer abc123'});
});

it('should authorize the request', async () => {
  const {auth, scopes} = mockGCE();
  const opts = await auth.authorizeRequest({url: 'http://example.com'});
  scopes.forEach(s => s.done());
  assert.deepEqual(opts.headers, {Authorization: 'Bearer abc123'});
});

it('should get the current environment if GCE', async () => {
  envDetect.clear();
  const {auth, scopes} = mockGCE();
  const env = await auth.getEnv();
  assert.equal(env, envDetect.GCPEnv.COMPUTE_ENGINE);
});

it('should get the current environment if GKE', async () => {
  envDetect.clear();
  const {auth, scopes} = mockGCE();
  const scope = nock(host)
                    .get(`${instancePath}/attributes/cluster-name`)
                    .reply(200, {}, HEADERS);
  const env = await auth.getEnv();
  assert.equal(env, envDetect.GCPEnv.KUBERNETES_ENGINE);
  scope.done();
});

it('should get the current environment if GCF', async () => {
  envDetect.clear();
  mockEnvVar('FUNCTION_NAME', 'DOGGY');
  const env = await auth.getEnv();
  assert.equal(env, envDetect.GCPEnv.CLOUD_FUNCTIONS);
});

it('should get the current environment if GAE', async () => {
  envDetect.clear();
  mockEnvVar('GAE_SERVICE', 'KITTY');
  const env = await auth.getEnv();
  assert.equal(env, envDetect.GCPEnv.APP_ENGINE);
});
