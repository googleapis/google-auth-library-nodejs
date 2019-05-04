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
import * as sinon from 'sinon';

import {JWTAccess} from '../src';
import * as messages from '../src/messages';

const keypair = require('keypair');

// Creates a standard JSON credentials object for testing.
const json = {
  private_key_id: 'key123',
  private_key: 'privatekey',
  client_email: 'hello@youarecool.com',
  client_id: 'client123',
  type: 'service_account',
};

const keys = keypair(1024 /* bitsize of private key */);
const testUri = 'http:/example.com/my_test_service';
const email = 'foo@serviceaccount.com';

let client: JWTAccess;
let sandbox: sinon.SinonSandbox;
beforeEach(() => {
  client = new JWTAccess();
  sandbox = sinon.createSandbox();
});
afterEach(() => {
  sandbox.restore();
});

it('should emit warning for createScopedRequired', () => {
  const stub = sandbox.stub(process, 'emitWarning');
  // tslint:disable-next-line deprecation
  client.createScopedRequired();
  assert(stub.called);
});

it('getRequestHeaders should create a signed JWT token as the access token', () => {
  const client = new JWTAccess(email, keys.private);
  const headers = client.getRequestHeaders(testUri);
  assert.notStrictEqual(null, headers, 'an creds object should be present');
  const decoded = jws.decode(headers.Authorization.replace('Bearer ', ''));
  assert.deepStrictEqual({alg: 'RS256', typ: 'JWT'}, decoded.header);
  const payload = decoded.payload;
  assert.strictEqual(email, payload.iss);
  assert.strictEqual(email, payload.sub);
  assert.strictEqual(testUri, payload.aud);
});

it('getRequestHeaders should set key id in header when available', () => {
  const client = new JWTAccess(email, keys.private, '101');
  const headers = client.getRequestHeaders(testUri);
  const decoded = jws.decode(headers.Authorization.replace('Bearer ', ''));
  assert.deepStrictEqual(
    {alg: 'RS256', typ: 'JWT', kid: '101'},
    decoded.header
  );
});

it('getRequestHeaders should not allow overriding with additionalClaims', () => {
  const client = new JWTAccess(email, keys.private);
  const additionalClaims = {iss: 'not-the-email'};
  assert.throws(() => {
    client.getRequestHeaders(testUri, additionalClaims);
  }, /^Error: The 'iss' property is not allowed when passing additionalClaims. This claim is included in the JWT by default.$/);
});

it('getRequestHeaders should return a cached token on the second request', () => {
  const client = new JWTAccess(email, keys.private);
  const res = client.getRequestHeaders(testUri);
  const res2 = client.getRequestHeaders(testUri);
  assert.strictEqual(res, res2);
});

it('getRequestHeaders should not return cached tokens older than an hour', () => {
  const client = new JWTAccess(email, keys.private);
  const res = client.getRequestHeaders(testUri);
  const realDateNow = Date.now;
  try {
    // go forward in time one hour (plus a little)
    Date.now = () => realDateNow() + 1000 * 60 * 60 + 10;
    const res2 = client.getRequestHeaders(testUri);
    assert.notStrictEqual(res, res2);
  } finally {
    // return date.now to it's normally scheduled programming
    Date.now = realDateNow;
  }
});

it('createScopedRequired should return false', () => {
  const client = new JWTAccess('foo@serviceaccount.com', null);
  // tslint:disable-next-line deprecation
  assert.strictEqual(false, client.createScopedRequired());
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
  assert.strictEqual(json.client_email, client.email);
});

it('fromJson should create JWT with private_key', () => {
  client.fromJSON(json);
  assert.strictEqual(json.private_key, client.key);
});

it('fromJson should create JWT with private_key_id', () => {
  client.fromJSON(json);
  assert.strictEqual(json.private_key_id, client.keyId);
});

it('fromStream should error on null stream', done => {
  // Test verifies invalid parameter tests, which requires cast to any.
  // tslint:disable-next-line no-any
  (client as any).fromStream(null, (err: Error) => {
    assert.strictEqual(true, err instanceof Error);
    done();
  });
});

it('fromStream should construct a JWT Header instance from a stream', async () => {
  // Read the contents of the file into a json object.
  const fileContents = fs.readFileSync('./test/fixtures/private.json', 'utf-8');
  const json = JSON.parse(fileContents);

  // Now open a stream on the same file.
  const stream = fs.createReadStream('./test/fixtures/private.json');

  // And pass it into the fromStream method.
  await client.fromStream(stream);
  // Ensure that the correct bits were pulled from the stream.
  assert.strictEqual(json.private_key, client.key);
  assert.strictEqual(json.client_email, client.email);
});

it('should warn about deprecation of getRequestMetadata', () => {
  const client = new JWTAccess(email, keys.private);
  const stub = sandbox.stub(messages, 'warn');
  // tslint:disable-next-line deprecation
  client.getRequestMetadata(testUri);
  assert.strictEqual(stub.calledOnce, true);
});
