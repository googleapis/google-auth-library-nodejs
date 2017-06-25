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
import JWTAccess from './../lib/auth/jwtaccess';

import GoogleAuth from '../lib/auth/googleauth';

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

describe('.getRequestMetadata', () => {

  it('create a signed JWT token as the access token', (done) => {
    const keys = keypair(1024 /* bitsize of private key */);
    const testUri = 'http:/example.com/my_test_service';
    const email = 'foo@serviceaccount.com';
    const auth = new GoogleAuth();
    const client = new auth.JWTAccess(email, keys.private);

    const retValue = 'dummy';
    const expectAuth = (err: Error, creds: any) => {
      assert.strictEqual(null, err, 'no error was expected: got\n' + err);
      assert.notStrictEqual(null, creds, 'an creds object should be present');
      const decoded = jws.decode(creds.Authorization.replace('Bearer ', ''));
      assert.strictEqual(email, decoded.payload.iss);
      assert.strictEqual(email, decoded.payload.sub);
      assert.strictEqual(testUri, decoded.payload.aud);
      done();
      return retValue;
    };
    const res = client.getRequestMetadata(testUri, expectAuth);
    assert.strictEqual(res, retValue);
  });

});

describe('.createScopedRequired', () => {

  it('should return false', () => {
    const auth = new GoogleAuth();
    const client = new auth.JWTAccess('foo@serviceaccount.com', null);

    assert.equal(false, client.createScopedRequired());
  });

});

describe('.fromJson', () => {
  // set up the test json and the client instance being tested.
  let json: any;
  let client: JWTAccess;
  beforeEach(() => {
    json = createJSON();
    const auth = new GoogleAuth();
    client = new auth.JWTAccess();
  });

  it('should error on null json', (done) => {
    client.fromJSON(null, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', (done) => {
    client.fromJSON({}, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_email', (done) => {
    delete json.client_email;

    client.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing private_key', (done) => {
    delete json.private_key;

    client.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create JWT with client_email', (done) => {
    client.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(json.client_email, client.email);
      done();
    });
  });

  it('should create JWT with private_key', (done) => {
    client.fromJSON(json, (err) => {
      assert.equal(null, err);
      assert.equal(json.private_key, client.key);
      done();
    });
  });

});

describe('.fromStream', () => {
  // set up the client instance being tested.
  let client: JWTAccess;
  beforeEach(() => {
    const auth = new GoogleAuth();
    client = new auth.JWTAccess();
  });

  it('should error on null stream', (done) => {
    client.fromStream(null, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should construct a JWT Header instance from a stream', (done) => {
    // Read the contents of the file into a json object.
    const fileContents =
        fs.readFileSync('./ts/test/fixtures/private.json', 'utf-8');
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./ts/test/fixtures/private.json');

    // And pass it into the fromStream method.
    client.fromStream(stream, (err) => {
      assert.equal(null, err);

      // Ensure that the correct bits were pulled from the stream.
      assert.equal(json.private_key, client.key);
      assert.equal(json.client_email, client.email);
      done();
    });
  });

});
