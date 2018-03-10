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
import {JWTAccess} from '../src/index';

const keypair = require('keypair');

// Creates a standard JSON credentials object for testing.
const json = {
  private_key_id: 'key123',
  private_key: 'privatekey',
  client_email: 'hello@youarecool.com',
  client_id: 'client123',
  type: 'service_account'
};

const keys = keypair(1024 /* bitsize of private key */);
const testUri = 'http:/example.com/my_test_service';
const email = 'foo@serviceaccount.com';
let client: JWTAccess;

beforeEach(() => {
  client = new JWTAccess();
});

it('getRequestMetadata should create a signed JWT token as the access token',
   () => {
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

it('getRequestMetadata should not allow overriding with additionalClaims', () => {
  const client = new JWTAccess(email, keys.private);
  const additionalClaims = {iss: 'not-the-email'};
  assert.throws(() => {
    client.getRequestMetadata(testUri, additionalClaims);
  }, `The 'iss' property is not allowed when passing additionalClaims. This claim is included in the JWT by default.`);
});

it('getRequestMetadata should return a cached token on the second request',
   () => {
     const client = new JWTAccess(email, keys.private);
     const res = client.getRequestMetadata(testUri);
     const res2 = client.getRequestMetadata(testUri);
     assert.strictEqual(res, res2);
   });

it('getRequestMetadata should not return cached tokens older than an hour',
   () => {
     const client = new JWTAccess(email, keys.private);
     const res = client.getRequestMetadata(testUri);
     const realDateNow = Date.now;
     try {
       // go forward in time one hour (plus a little)
       Date.now = () => realDateNow() + (1000 * 60 * 60) + 10;
       const res2 = client.getRequestMetadata(testUri);
       assert.notEqual(res, res2);
     } finally {
       // return date.now to it's normally scheduled programming
       Date.now = realDateNow;
     }
   });

it('fromJson should error on null json', () => {
  assert.throws(() => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (client as any).fromJSON(null);
  });
});

it('fromJson should error on empty json', () => {
  assert.throws(() => {
    client.fromJSON({});
  });
});

it('fromJson should error on missing client_email', () => {
  const j = Object.assign({}, json);
  delete j.client_email;
  assert.throws(() => {
    client.fromJSON(j);
  });
});

it('fromJson should error on missing private_key', () => {
  const j = Object.assign({}, json);
  delete j.private_key;
  assert.throws(() => {
    client.fromJSON(j);
  });
});

it('fromJson should create JWT with client_email', () => {
  client.fromJSON(json);
  assert.equal(json.client_email, client.email);
});

it('fromJson should create JWT with private_key', () => {
  client.fromJSON(json);
  assert.equal(json.private_key, client.key);
});

it('fromStream should error on null stream', (done) => {
  // Test verifies invalid parameter tests, which requires cast to any.
  // tslint:disable-next-line no-any
  (client as any).fromStream(null, (err: Error) => {
    assert.equal(true, err instanceof Error);
    done();
  });
});

it('fromStream should construct a JWT Header instance from a stream',
   async () => {
     // Read the contents of the file into a json object.
     const fileContents =
         fs.readFileSync('./test/fixtures/private.json', 'utf-8');
     const json = JSON.parse(fileContents);

     // Now open a stream on the same file.
     const stream = fs.createReadStream('./test/fixtures/private.json');

     // And pass it into the fromStream method.
     await client.fromStream(stream);
     // Ensure that the correct bits were pulled from the stream.
     assert.equal(json.private_key, client.key);
     assert.equal(json.client_email, client.email);
   });
