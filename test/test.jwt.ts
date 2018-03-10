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

import * as assert from 'assert';
import * as fs from 'fs';
import * as jws from 'jws';
import * as nock from 'nock';

import {CredentialRequest, JWTInput} from '../src/auth/credentials';
import {GoogleAuth, JWT} from '../src/index';

const keypair = require('keypair');
const PEM_PATH = './test/fixtures/private.pem';
const PEM_CONTENTS = fs.readFileSync(PEM_PATH, 'utf8');

nock.disableNetConnect();

// Creates a standard JSON credentials object for testing.
function createJSON() {
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

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
      .post('/oauth2/v4/token')
      .reply(200, body);
}

// set up the test json and the jwt instance being tested.
let jwt: JWT;
let json: JWTInput;
beforeEach(() => {
  json = createJSON();
  jwt = new JWT();
});

afterEach(() => {
  nock.cleanAll();
});

it('should create a dummy refresh token string', () => {
  // It is important that the compute client is created with a refresh token
  // value filled in, or else the rest of the logic will not work.
  const jwt = new JWT();
  assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
});

it('should get an initial access token', done => {
  const jwt = new JWT(
      'foo@serviceaccount.com', PEM_PATH, undefined,
      ['http://bar', 'http://foo'], 'bar@subjectaccount.com');
  createGTokenMock({access_token: 'initial-access-token'});
  jwt.authorize((err, creds) => {
    assert.equal(err, null);
    assert.notEqual(creds, null);
    assert.equal('foo@serviceaccount.com', jwt.gtoken!.iss);
    assert.equal(PEM_PATH, jwt.gtoken!.keyFile);
    assert.equal(['http://bar', 'http://foo'].join(' '), jwt.gtoken!.scope);
    assert.equal('bar@subjectaccount.com', jwt.gtoken!.sub);
    assert.equal('initial-access-token', jwt.credentials.access_token);
    assert.equal(creds!.access_token, jwt.credentials.access_token);
    assert.equal(creds!.refresh_token, jwt.credentials.refresh_token);
    assert.equal(creds!.token_type, jwt.credentials.token_type);
    assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
    assert.equal(PEM_CONTENTS, jwt.key);
    assert.equal('foo@serviceaccount.com', jwt.email);
    done();
  });
});

it('should accept scope as string', done => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: 'http://foo',
    subject: 'bar@subjectaccount.com'
  });

  createGTokenMock({access_token: 'initial-access-token'});
  jwt.authorize((err, creds) => {
    assert.equal('http://foo', jwt.gtoken!.scope);
    done();
  });
});

it('can get obtain new access token when scopes are set', (done) => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {refresh_token: 'jwt-placeholder'};
  createGTokenMock({access_token: 'initial-access-token'});
  jwt.getAccessToken((err, got) => {
    assert.strictEqual(null, err, 'no error was expected: got\n' + err);
    assert.strictEqual(
        'initial-access-token', got, 'the access token was wrong: ' + got);
    done();
  });
});

it('can obtain new access token when scopes are set', (done) => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });
  jwt.credentials = {refresh_token: 'jwt-placeholder'};

  const wantedToken = 'abc123';
  const want = 'Bearer ' + wantedToken;
  createGTokenMock({access_token: wantedToken});
  jwt.getRequestMetadata(undefined, (err, result) => {
    assert.strictEqual(null, err, 'no error was expected: got\n' + err);
    const got = result as {
      Authorization: string;
    };
    assert.strictEqual(
        want, got.Authorization,
        'the authorization header was wrong: ' + got.Authorization);
    done();
  });
});

it('gets a jwt header access token', (done) => {
  const keys = keypair(1024 /* bitsize of private key */);
  const email = 'foo@serviceaccount.com';
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com'
  });
  jwt.credentials = {refresh_token: 'jwt-placeholder'};

  const testUri = 'http:/example.com/my_test_service';
  jwt.getRequestMetadata(testUri, (err, result) => {
    const got = result as {
      Authorization: string;
    };
    assert.strictEqual(null, err, 'no error was expected: got\n' + err);
    assert.notStrictEqual(null, got, 'the creds should be present');
    const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
    const payload = JSON.parse(decoded.payload);
    assert.strictEqual(email, payload.iss);
    assert.strictEqual(email, payload.sub);
    assert.strictEqual(testUri, payload.aud);
    done();
  });
});

it('should accept additionalClaims', async () => {
  const keys = keypair(1024 /* bitsize of private key */);
  const email = 'foo@serviceaccount.com';
  const someClaim = 'cat-on-my-desk';
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com',
    additionalClaims: {someClaim}
  });
  jwt.credentials = {refresh_token: 'jwt-placeholder'};

  const testUri = 'http:/example.com/my_test_service';
  const {headers} = await jwt.getRequestMetadata(testUri);
  const got = headers as {
    Authorization: string;
  };
  assert.notStrictEqual(null, got, 'the creds should be present');
  const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
  const payload = JSON.parse(decoded.payload);
  assert.strictEqual(testUri, payload.aud);
  assert.strictEqual(someClaim, payload.someClaim);
});

it('should accept additionalClaims that include a target_audience',
   async () => {
     const keys = keypair(1024 /* bitsize of private key */);
     const email = 'foo@serviceaccount.com';
     const jwt = new JWT({
       email: 'foo@serviceaccount.com',
       key: keys.private,
       subject: 'ignored@subjectaccount.com',
       additionalClaims: {target_audience: 'applause'}
     });
     jwt.credentials = {refresh_token: 'jwt-placeholder'};

     const testUri = 'http:/example.com/my_test_service';
     createGTokenMock({access_token: 'abc123'});
     const {headers} = await jwt.getRequestMetadata(testUri);
     const got = headers as {
       Authorization: string;
     };
     assert.notStrictEqual(null, got, 'the creds should be present');
     const decoded = got.Authorization.replace('Bearer ', '');
     assert.strictEqual(decoded, 'abc123');
   });

it('should refresh token if missing access token', (done) => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });
  jwt.credentials = {refresh_token: 'jwt-placeholder'};
  createGTokenMock({access_token: 'abc123'});

  jwt.request({url: 'http://bar'}, () => {
    assert.equal('abc123', jwt.credentials.access_token);
    done();
  });
});

it('should refresh token if expired', (done) => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {
    access_token: 'woot',
    refresh_token: 'jwt-placeholder',
    expiry_date: (new Date()).getTime() - 1000
  };

  createGTokenMock({access_token: 'abc123'});
  jwt.request({url: 'http://bar'}, () => {
    assert.equal('abc123', jwt.credentials.access_token);
    done();
  });
});

it('should refresh if access token will expired soon and time to refresh before expiration is set',
   (done) => {
     const auth = new GoogleAuth();
     const jwt = new JWT({
       email: 'foo@serviceaccount.com',
       keyFile: PEM_PATH,
       scopes: ['http://bar', 'http://foo'],
       subject: 'bar@subjectaccount.com',
       eagerRefreshThresholdMillis: 1000
     });

     jwt.credentials = {
       access_token: 'woot',
       refresh_token: 'jwt-placeholder',
       expiry_date: (new Date()).getTime() + 800
     };

     createGTokenMock({access_token: 'abc123'});
     jwt.request({url: 'http://bar'}, () => {
       assert.equal('abc123', jwt.credentials.access_token);
       done();
     });
   });

it('should not refresh if access token will not expire soon and time to refresh before expiration is set',
   done => {
     const scope =
         createGTokenMock({access_token: 'abc123', expires_in: 10000});
     const jwt = new JWT({
       email: 'foo@serviceaccount.com',
       keyFile: '/path/to/key.pem',
       scopes: ['http://bar', 'http://foo'],
       subject: 'bar@subjectaccount.com',
       eagerRefreshThresholdMillis: 1000
     });

     jwt.credentials = {
       access_token: 'initial-access-token',
       refresh_token: 'jwt-placeholder',
       expiry_date: (new Date()).getTime() + 5000
     };

     jwt.request({url: 'http://bar'}, () => {
       assert.equal('initial-access-token', jwt.credentials.access_token);
       assert.equal(false, scope.isDone());
       done();
     });
   });

it('should refresh token if the server returns 403', (done) => {
  nock('http://example.com').get('/access').twice().reply(403);
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://example.com'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {
    access_token: 'woot',
    refresh_token: 'jwt-placeholder',
    expiry_date: (new Date()).getTime() + 5000
  };

  createGTokenMock({access_token: 'abc123'});

  jwt.request({url: 'http://example.com/access'}, () => {
    assert.equal('abc123', jwt.credentials.access_token);
    done();
  });
});

it('should not refresh if not expired', (done) => {
  const scope = createGTokenMock({access_token: 'abc123', expires_in: 10000});
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'jwt-placeholder',
    expiry_date: (new Date()).getTime() + 5000
  };

  jwt.request({url: 'http://bar'}, () => {
    assert.equal('initial-access-token', jwt.credentials.access_token);
    assert.equal(false, scope.isDone());
    done();
  });
});

it('should assume access token is not expired', (done) => {
  const scope = createGTokenMock({access_token: 'abc123', expires_in: 10000});
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {
    access_token: 'initial-access-token',
    refresh_token: 'jwt-placeholder'
  };

  jwt.request({url: 'http://bar'}, () => {
    assert.equal('initial-access-token', jwt.credentials.access_token);
    assert.equal(false, scope.isDone());
    done();
  });
});

it('should return expiry_date in milliseconds', async () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: PEM_PATH,
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });

  jwt.credentials = {refresh_token: 'jwt-placeholder'};

  createGTokenMock({access_token: 'token', expires_in: 100});
  const result = await jwt.refreshToken();
  const creds = result.tokens;
  const dateInMillis = (new Date()).getTime();
  const expiryDate = new Date(creds.expiry_date!);
  assert.equal(
      dateInMillis.toString().length, creds.expiry_date!.toString().length);
});

it('hasScopes should return false when scopes is null', () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    subject: 'bar@subjectaccount.com'
  });
  assert.equal(false, jwt.hasScopes());
});

it('hasScopes should return false when scopes is an empty array', () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: [],
    subject: 'bar@subjectaccount.com'
  });
  assert.equal(false, jwt.hasScopes());
});

it('hasScopes should return false when scopes is an empty string', () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: '',
    subject: 'bar@subjectaccount.com'
  });
  assert.equal(false, jwt.hasScopes());
});

it('hasScopes should return true when scopes is a filled-in string', () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: 'http://foo',
    subject: 'bar@subjectaccount.com'
  });
  assert.equal(true, jwt.hasScopes());
});

it('hasScopes should return true when scopes is a filled-in array', () => {
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    keyFile: '/path/to/key.pem',
    scopes: ['http://bar', 'http://foo'],
    subject: 'bar@subjectaccount.com'
  });
  assert.equal(true, jwt.hasScopes());
});

it('hasScopes should return true when scopes is not an array or a string, but can be used as a string',
   () => {
     const jwt = new JWT({
       email: 'foo@serviceaccount.com',
       keyFile: '/path/to/key.pem',
       scopes: '2',
       subject: 'bar@subjectaccount.com'
     });
     assert.equal(true, jwt.hasScopes());
   });

it('fromJson should error on null json', () => {
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (jwt as any).fromJSON(null);
  });
});

it('fromJson should error on empty json', () => {
  assert.throws(() => {
    jwt.fromJSON({});
  });
});

it('fromJson should error on missing client_email', () => {
  delete json.client_email;
  assert.throws(() => {
    jwt.fromJSON(json);
  });
});

it('fromJson should error on missing private_key', () => {
  delete json.private_key;
  assert.throws(() => {
    jwt.fromJSON(json);
  });
});

it('fromJson should create JWT with client_email', () => {
  const result = jwt.fromJSON(json);
  assert.equal(json.client_email, jwt.email);
});

it('fromJson should create JWT with private_key', () => {
  const result = jwt.fromJSON(json);
  assert.equal(json.private_key, jwt.key);
});

it('fromJson should create JWT with null scopes', () => {
  const result = jwt.fromJSON(json);
  assert.equal(null, jwt.scopes);
});

it('fromJson should create JWT with null subject', () => {
  const result = jwt.fromJSON(json);
  assert.equal(null, jwt.subject);
});

it('fromJson should create JWT with null keyFile', () => {
  const result = jwt.fromJSON(json);
  assert.equal(null, jwt.keyFile);
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

it('fromStream should error on null stream', (done) => {
  // Test verifies invalid parameter tests, which requires cast to any.
  // tslint:disable-next-line no-any
  (jwt as any).fromStream(null, (err: Error) => {
    assert.equal(true, err instanceof Error);
    done();
  });
});

it('fromStream should read the stream and create a jwt', (done) => {
  // Read the contents of the file into a json object.
  const fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
  const json = JSON.parse(fileContents);

  // Now open a stream on the same file.
  const stream = fs.createReadStream('./test/fixtures/private.json');

  // And pass it into the fromStream method.
  jwt.fromStream(stream, (err) => {
    assert.equal(null, err);
    // Ensure that the correct bits were pulled from the stream.
    assert.equal(json.private_key, jwt.key);
    assert.equal(json.client_email, jwt.email);
    assert.equal(null, jwt.keyFile);
    assert.equal(null, jwt.subject);
    assert.equal(null, jwt.scopes);
    done();
  });
});

it('fromAPIKey should error without api key', () => {
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (jwt as any).fromAPIKey(undefined);
  });
});

it('fromAPIKey should error with invalid api key type', () => {
  const KEY = 'test';
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    jwt.fromAPIKey({key: KEY} as any);
  });
});

it('fromAPIKey should set the .apiKey property on the instance', () => {
  const KEY = 'test';
  const result = jwt.fromAPIKey(KEY);
  assert.strictEqual(jwt.apiKey, KEY);
});
