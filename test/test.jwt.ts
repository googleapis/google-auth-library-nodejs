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
import {JWTInput} from '../src/auth/credentials';
import {GoogleAuth} from '../src/auth/googleauth';
import {JWT} from '../src/auth/jwtclient';

const keypair = require('keypair');
const noop = Function.prototype;

interface TokenCallback {
  (err: Error|null, result: string): void;
}

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

interface GTokenResult {
  access_token?: string;
  expires_in?: number;
}

function createGTokenMock(body: GTokenResult = {
  access_token: 'initial-access-token'
}) {
  nock('https://accounts.google.com:443')
      .post('/o/oauth2/token')
      .reply(200, body);
}

afterEach(() => {
  nock.cleanAll();
});

describe('Initial credentials', () => {
  it('should create a dummy refresh token string', () => {
    // It is important that the compute client is created with a refresh token
    // value filled in, or else the rest of the logic will not work.
    const auth = new GoogleAuth();
    const jwt = new auth.JWT();
    assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
  });
});

describe('JWT auth client', () => {
  describe('.authorize', () => {
    it('should get an initial access token', done => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', PEM_PATH, null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      createGTokenMock();
      jwt.authorize(() => {
        assert.equal('foo@serviceaccount.com', jwt.gtoken.iss);
        assert.equal(PEM_PATH, jwt.gtoken.keyFile);
        assert.equal(['http://bar', 'http://foo'].join(' '), jwt.gtoken.scope);
        assert.equal('bar@subjectaccount.com', jwt.gtoken.sub);
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
        assert.equal(PEM_CONTENTS, jwt.key);
        assert.equal('foo@serviceaccount.com', jwt.email);
        done();
      });
    });

    it('should accept scope as string', done => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null, 'http://foo',
          'bar@subjectaccount.com');

      createGTokenMock();
      jwt.authorize((err, creds) => {
        assert.equal('http://foo', jwt.gtoken.scope);
        done();
      });
    });
  });

  describe('.getAccessToken', () => {
    describe('when scopes are set', () => {
      it('can get obtain new access token', (done) => {
        const auth = new GoogleAuth();
        const jwt = new auth.JWT(
            'foo@serviceaccount.com', PEM_PATH, null,
            ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {refresh_token: 'jwt-placeholder'};
        createGTokenMock();
        jwt.getAccessToken((err, got) => {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.strictEqual(
              'initial-access-token', got,
              'the access token was wrong: ' + got);
          done();
        });
      });
    });
  });

  describe('.getRequestMetadata', () => {
    describe('when scopes are set', () => {
      it('can obtain new access token', (done) => {
        const auth = new GoogleAuth();
        const jwt = new auth.JWT(
            'foo@serviceaccount.com', PEM_PATH, null,
            ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {refresh_token: 'jwt-placeholder'};

        const wantedToken = 'abc123';
        const want = 'Bearer ' + wantedToken;
        createGTokenMock({access_token: wantedToken});
        jwt.getRequestMetadata(null, (err, result) => {
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
    });

    describe('when scopes are not set, but a uri is provided', () => {
      it('gets a jwt header access token', (done) => {
        const keys = keypair(1024 /* bitsize of private key */);
        const email = 'foo@serviceaccount.com';
        const auth = new GoogleAuth();
        const jwt = new auth.JWT(
            'foo@serviceaccount.com', null, keys.private, null,
            'ignored@subjectaccount.com');

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
    });
  });

  describe('.request', () => {
    it('should refresh token if missing access token', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', PEM_PATH, null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      createGTokenMock({access_token: 'abc123'});

      jwt.request({url: 'http://bar'}, () => {
        assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if expired', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', PEM_PATH, null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

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

    it('should refresh token if the server returns 403', (done) => {
      nock('http://example.com').get('/access').twice().reply(403);

      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', PEM_PATH, null, ['http://example.com'],
          'bar@subjectaccount.com');

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
      const scope =
          nock('https://accounts.google.com')
              .post('/o/oauth2/token', '*')
              .reply(200, {access_token: 'abc123', expires_in: 10000});

      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

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
      const scope =
          nock('https://accounts.google.com')
              .post('/o/oauth2/token', '*')
              .reply(200, {access_token: 'abc123', expires_in: 10000});

      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

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
  });

  it('should return expiry_date in milliseconds', async () => {
    const auth = new GoogleAuth();
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', PEM_PATH, null, ['http://bar', 'http://foo'],
        'bar@subjectaccount.com');

    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    createGTokenMock({access_token: 'token', expires_in: 100});
    const result = await jwt.refreshToken(null);
    const creds = result.tokens;
    const dateInMillis = (new Date()).getTime();
    const expiryDate = new Date(creds.expiry_date!);
    assert.equal(
        dateInMillis.toString().length, creds.expiry_date!.toString().length);
  });
});

describe('.createScoped', () => {
  // set up the auth module.
  let auth: GoogleAuth;
  beforeEach(() => {
    auth = new GoogleAuth();
  });

  it('should clone stuff', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    const clone = jwt.createScoped('x');

    assert.equal(jwt.email, clone.email);
    assert.equal(jwt.keyFile, clone.keyFile);
    assert.equal(jwt.key, clone.key);
    assert.equal(jwt.subject, clone.subject);
  });

  it('should handle string scope', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    const clone = jwt.createScoped('newscope');
    assert.equal('newscope', clone.scopes);
  });

  it('should handle array scope', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    const clone = jwt.createScoped(['gorilla', 'chimpanzee', 'orangutan']);
    assert.equal(3, clone.scopes!.length);
    assert.equal('gorilla', clone.scopes![0]);
    assert.equal('chimpanzee', clone.scopes![1]);
    assert.equal('orangutan', clone.scopes![2]);
  });

  it('should handle null scope', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    const clone = jwt.createScoped();
    assert.equal(null, clone.scopes);
  });

  it('should set scope when scope was null', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null, null,
        'bar@subjectaccount.com');

    const clone = jwt.createScoped('hi');
    assert.equal('hi', clone.scopes);
  });

  it('should handle nulls', () => {
    const jwt = new auth.JWT();

    const clone = jwt.createScoped('hi');
    assert.equal(jwt.email, null);
    assert.equal(jwt.keyFile, null);
    assert.equal(jwt.key, null);
    assert.equal(jwt.subject, null);
    assert.equal('hi', clone.scopes);
  });

  it('should not return the original instance', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    const clone = jwt.createScoped('hi');
    assert.notEqual(jwt, clone);
  });
});

describe('.createScopedRequired', () => {
  // set up the auth module.
  let auth: GoogleAuth;
  beforeEach(() => {
    auth = new GoogleAuth();
  });

  it('should return true when scopes is null', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null, null,
        'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty array', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null, [],
        'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return true when scopes is an empty string', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null, '',
        'bar@subjectaccount.com');

    assert.equal(true, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in string', () => {
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null, 'http://foo',
        'bar@subjectaccount.com');

    assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is a filled-in array', () => {
    const auth2 = new GoogleAuth();
    const jwt = new auth2.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    assert.equal(false, jwt.createScopedRequired());
  });

  it('should return false when scopes is not an array or a string, but can be used as a string',
     () => {
       const auth2 = new GoogleAuth();
       const jwt = new auth2.JWT(
           'foo@serviceaccount.com', '/path/to/key.pem', null, '2',
           'bar@subjectaccount.com');

       assert.equal(false, jwt.createScopedRequired());
     });
});

describe('.fromJson', () => {
  // set up the test json and the jwt instance being tested.
  let jwt: JWT;
  let json: JWTInput;
  beforeEach(() => {
    json = createJSON();
    const auth = new GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null json', (done) => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (jwt as any).fromJSON(null, (err: Error) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', (done) => {
    jwt.fromJSON({}, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', (done) => {
    delete json.client_email;

    jwt.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', (done) => {
    delete json.private_key;

    jwt.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', (done) => {
    jwt.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(json.client_email, jwt.email);
      done();
    });
  });

  it('should create JWT with private_key', (done) => {
    jwt.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(json.private_key, jwt.key);
      done();
    });
  });

  it('should create JWT with null scopes', (done) => {
    jwt.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(null, jwt.scopes);
      done();
    });
  });

  it('should create JWT with null subject', (done) => {
    jwt.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(null, jwt.subject);
      done();
    });
  });

  it('should create JWT with null keyFile', (done) => {
    jwt.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(null, jwt.keyFile);
      done();
    });
  });
});

describe('.fromStream', () => {
  // set up the jwt instance being tested.
  let jwt: JWT;
  beforeEach(() => {
    const auth = new GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null stream', (done) => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (jwt as any).fromStream(null, (err: Error) => {
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
});

describe('.fromAPIKey', () => {
  let jwt: JWT;
  const KEY = 'test';
  beforeEach(() => {
    const auth = new GoogleAuth();
    jwt = new auth.JWT();
  });
  describe('exception behaviour', () => {
    it('should error without api key', (done) => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // tslint:disable-next-line no-any
      (jwt as any).fromAPIKey(undefined, (err: Error) => {
        assert(err instanceof Error);
        done();
      });
    });
    it('should error with invalid api key type', (done) => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // tslint:disable-next-line no-any
      jwt.fromAPIKey(({key: KEY} as any), (err) => {
        assert(err instanceof Error);
        done();
      });
    });
  });

  describe('Valid behaviour', () => {
    it('should set the .apiKey property on the instance', (done) => {
      jwt.fromAPIKey(KEY, (err) => {
        assert.strictEqual(jwt.apiKey, KEY);
        assert.equal(err, null);
        done();
      });
    });
  });
});
