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
const jws = require('jws');
const keypair = require('keypair');
import * as nock from 'nock';

import {GoogleAuth} from '../lib/auth/googleauth';
import {JWT} from '../lib/auth/jwtclient';

const noop = Function.prototype;
interface TokenCallback {
  (err: Error, result: string): void;
}

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

    it('should get an initial access token', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');
      jwt.gToken = (opts: any) => {
        assert.equal('foo@serviceaccount.com', opts.iss);
        assert.equal('/path/to/key.pem', opts.keyFile);
        assert.deepEqual(['http://bar', 'http://foo'], opts.scope);
        assert.equal('bar@subjectaccount.com', opts.sub);
        return {
          key: 'private-key-data',
          iss: 'foo@subjectaccount.com',
          getToken: (opt_callback: Function) => {
            return opt_callback(null, 'initial-access-token');
          }
        };
      };
      jwt.authorize(() => {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal('jwt-placeholder', jwt.credentials.refresh_token);
        assert.equal('private-key-data', jwt.key);
        assert.equal('foo@subjectaccount.com', jwt.email);
        done();
      });
    });

    it('should accept scope as string', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null, 'http://foo',
          'bar@subjectaccount.com');

      jwt.gToken = (opts: any) => {
        assert.equal('http://foo', opts.scope);
        done();
        return {getToken: noop};
      };

      jwt.authorize();
    });

  });

  describe('.getAccessToken', () => {

    describe('when scopes are set', () => {

      it('can get obtain new access token', (done) => {
        const auth = new GoogleAuth();
        const jwt = new auth.JWT(
            'foo@serviceaccount.com', '/path/to/key.pem', null,
            ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {refresh_token: 'jwt-placeholder'};

        const want = 'abc123';
        jwt.gtoken = {
          getToken: (callback: (err: Error, want: string) => void) => {
            return callback(null, want);
          }
        };

        jwt.getAccessToken((err, got) => {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.strictEqual(want, got, 'the access token was wrong: ' + got);
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
            'foo@serviceaccount.com', '/path/to/key.pem', null,
            ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

        jwt.credentials = {refresh_token: 'jwt-placeholder'};

        const wanted_token = 'abc123';
        jwt.gtoken = {
          getToken: (callback: (err: Error, wanted_token: string) => void) => {
            return callback(null, wanted_token);
          }
        };
        const want = 'Bearer ' + wanted_token;
        const retValue = 'dummy';
        const res = jwt.getRequestMetadata(null, (err, got) => {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.strictEqual(
              want, got.Authorization,
              'the authorization header was wrong: ' + got.Authorization);
          done();
          return retValue;
        });
        assert.strictEqual(res, retValue);
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
        const retValue = 'dummy';
        const res = jwt.getRequestMetadata(testUri, (err, got) => {
          assert.strictEqual(null, err, 'no error was expected: got\n' + err);
          assert.notStrictEqual(null, got, 'the creds should be present');
          const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
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

  describe('.request', () => {

    it('should refresh token if missing access token', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {refresh_token: 'jwt-placeholder'};

      jwt.gtoken = {
        getToken: (callback: (err: Error, result: string) => void) => {
          callback(null, 'abc123');
        }
      };

      jwt.request({uri: 'http://bar'}, () => {
        assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if expired', (done) => {
      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() - 1000
      };

      jwt.gtoken = {
        getToken: (callback: TokenCallback) => {
          return callback(null, 'abc123');
        }
      };

      jwt.request({uri: 'http://bar'}, () => {
        assert.equal('abc123', jwt.credentials.access_token);
        done();
      });
    });

    it('should refresh token if the server returns 403', (done) => {
      nock('http://example.com').log(console.log).get('/access').reply(403);

      const auth = new GoogleAuth();
      const jwt = new auth.JWT(
          'foo@serviceaccount.com', '/path/to/key.pem', null,
          ['http://example.com'], 'bar@subjectaccount.com');

      jwt.credentials = {
        access_token: 'woot',
        refresh_token: 'jwt-placeholder',
        expiry_date: (new Date()).getTime() + 5000
      };

      jwt.gtoken = {
        getToken: (callback: TokenCallback) => {
          return callback(null, 'abc123');
        }
      };

      jwt.request({uri: 'http://example.com/access'}, () => {
        assert.equal('abc123', jwt.credentials.access_token);
        nock.cleanAll();
        done();
      });
    });

    it('should not refresh if not expired', (done) => {
      const scope =
          nock('https://accounts.google.com')
              .log(console.log)
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

      jwt.request({uri: 'http://bar'}, () => {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal(false, scope.isDone());
        nock.cleanAll();
        done();
      });
    });

    it('should assume access token is not expired', (done) => {
      const scope =
          nock('https://accounts.google.com')
              .log(console.log)
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

      jwt.request({uri: 'http://bar'}, () => {
        assert.equal('initial-access-token', jwt.credentials.access_token);
        assert.equal(false, scope.isDone());
        nock.cleanAll();
        done();
      });
    });

  });

  it('should return expiry_date in milliseconds', (done) => {
    const auth = new GoogleAuth();
    const jwt = new auth.JWT(
        'foo@serviceaccount.com', '/path/to/key.pem', null,
        ['http://bar', 'http://foo'], 'bar@subjectaccount.com');

    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const dateInMillis = (new Date()).getTime();

    jwt.gtoken = {
      getToken: (callback: TokenCallback) => {
        return callback(null, 'token');
      },
      expires_at: dateInMillis
    };

    jwt.refreshToken({uri: 'http://bar'}, (err, creds) => {
      assert.equal(dateInMillis, creds.expiry_date);
      done();
    });
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
    assert.equal(3, clone.scopes.length);
    assert.equal('gorilla', clone.scopes[0]);
    assert.equal('chimpanzee', clone.scopes[1]);
    assert.equal('orangutan', clone.scopes[2]);
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
  let json: any;
  beforeEach(() => {
    json = createJSON();
    const auth = new GoogleAuth();
    jwt = new auth.JWT();
  });

  it('should error on null json', (done) => {
    jwt.fromJSON(null, (err) => {
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
    jwt.fromStream(null, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a jwt', (done) => {
    // Read the contents of the file into a json object.
    const fileContents =
        fs.readFileSync('./ts/test/fixtures/private.json', 'utf-8');
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./ts/test/fixtures/private.json');

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
      jwt.fromAPIKey(undefined, (err) => {
        assert(err instanceof Error);
        done();
      });
    });
    it('should error with invalid api key type', (done) => {
      jwt.fromAPIKey({key: KEY} as any, (err) => {
        assert(err instanceof Error);
        done();
      });
    });
  });

  describe('Valid behaviour', () => {
    it('should set the .apiKey property on the instance', (done) => {
      jwt.fromAPIKey(KEY, (err) => {
        assert.strictEqual(jwt.apiKey, KEY);
        assert.strictEqual(err, null);
        done();
      });
    });
  });
});
