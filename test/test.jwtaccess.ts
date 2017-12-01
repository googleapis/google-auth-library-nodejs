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
import * as http from 'http';
import * as jws from 'jws';

import {JWTInput} from '../src/auth/credentials';
import {GoogleAuth, JWTAccess} from '../src/index';

const keypair = require('keypair');

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
  it('create a signed JWT token as the access token', () => {
    const keys = keypair(1024 /* bitsize of private key */);
    const testUri = 'http:/example.com/my_test_service';
    const email = 'foo@serviceaccount.com';
    const client = new JWTAccess(email, keys.private);
    const res = client.getRequestMetadata(testUri);
    assert.notStrictEqual(
        null, res.headers, 'an creds object should be present');
    const decoded = jws.decode(
        (res.headers!.Authorization as string).replace('Bearer ', ''));
    const payload = JSON.parse(decoded.payload);
    assert.strictEqual(email, payload.iss);
    assert.strictEqual(email, payload.sub);
    assert.strictEqual(testUri, payload.aud);
  });
});

describe('.createScopedRequired', () => {
  it('should return false', () => {
    const client = new JWTAccess('foo@serviceaccount.com', null);
    assert.equal(false, client.createScopedRequired());
  });
});

describe('.fromJson', () => {
  // set up the test json and the client instance being tested.
  let json = ({} as JWTInput);
  let client: JWTAccess;
  beforeEach(() => {
    json = createJSON();
    client = new JWTAccess();
  });

  it('should error on null json', () => {
    assert.throws(() => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // tslint:disable-next-line no-any
      (client as any).fromJSON(null);
    });
  });

  it('should error on empty json', () => {
    assert.throws(() => {
      client.fromJSON({});
    });
  });

  it('should error on missing client_email', () => {
    delete json.client_email;
    assert.throws(() => {
      client.fromJSON(json);
    });
  });

  it('should error on missing private_key', () => {
    delete json.private_key;
    assert.throws(() => {
      client.fromJSON(json);
    });
  });

  it('should create JWT with client_email', () => {
    const result = client.fromJSON(json);
    assert.equal(json.client_email, client.email);
  });

  it('should create JWT with private_key', () => {
    const result = client.fromJSON(json);
    assert.equal(json.private_key, client.key);
  });
});

describe('.fromStream', () => {
  // set up the client instance being tested.
  let client: JWTAccess;
  beforeEach(() => {
    client = new JWTAccess();
  });

  it('should error on null stream', (done) => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (client as any).fromStream(null, (err: Error) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should construct a JWT Header instance from a stream', (done) => {
    // Read the contents of the file into a json object.
    const fileContents =
        fs.readFileSync('./test/fixtures/private.json', 'utf-8');
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./test/fixtures/private.json');

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
