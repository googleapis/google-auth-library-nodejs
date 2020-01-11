// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import * as assert from 'assert';
import {it} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';

import {IdTokenClient, JWT} from '../src';
import {CredentialRequest} from '../src/auth/credentials';

const keypair = require('keypair');

nock.disableNetConnect();

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, body);
}

let sandbox: sinon.SinonSandbox;
beforeEach(() => {
  sandbox = sinon.createSandbox();
});

afterEach(() => {
  nock.cleanAll();
  sandbox.restore();
});

it('should determine expiry_date from JWT', async () => {
  const keys = keypair(1024 /* bitsize of private key */);
  const idToken = 'header.eyJleHAiOiAxNTc4NzAyOTU2fQo.signature';
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com',
  });

  const scope = createGTokenMock({id_token: idToken});
  const targetAudience = 'a-target-audience';
  const client = new IdTokenClient({idTokenProvider: jwt, targetAudience});
  await client.getRequestHeaders();
  scope.done();
  assert.strictEqual(client.credentials.expiry_date, 1578702956000);
});

it('should refresh ID token if expired', async () => {
  const keys = keypair(1024 /* bitsize of private key */);
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com',
  });

  const scope = createGTokenMock({id_token: 'abc123'});
  const targetAudience = 'a-target-audience';
  const client = new IdTokenClient({idTokenProvider: jwt, targetAudience});
  client.credentials = {
    id_token: 'an-identity-token',
    expiry_date: new Date().getTime() - 1000,
  };
  await client.getRequestHeaders();
  scope.done();
  assert.strictEqual(client.credentials.id_token, 'abc123');
});
