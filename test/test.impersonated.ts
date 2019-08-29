/**
 * Copyright 2019 Google LLC
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
import * as nock from 'nock';
import * as sinon from 'sinon';
import { Impersonated, JWT } from '../src';
import { CredentialRequest } from '../src/auth/credentials';
const assertRejects = require('assert-rejects');

const keypair = require('keypair');
const PEM_PATH = './test/fixtures/private.pem';
const PEM_CONTENTS = fs.readFileSync(PEM_PATH, 'utf8');
const P12_PATH = './test/fixtures/key.p12';

nock.disableNetConnect();

const url = 'http://example.com';

function mockExample() {
  return nock(url)
    .get('/')
    .reply(200);
}

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, body);
}

// set up impresonated client.
const sandbox = sinon.createSandbox();
let impersonated: Impersonated;
beforeEach(() => {
  const jwt = new JWT(
    'foo@serviceaccount.com',
    PEM_PATH,
    undefined,
    ['http://bar', 'http://foo'],
    'bar@subjectaccount.com'
  );
  const scope = createGTokenMock({ access_token: 'initial-access-token' });
  jwt.authorize((err, creds) => {
    scope.done();
    impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: "target@project.iam.gserviceaccount.com",
      lifetime: 30,
      delegates: [],
      targetScopes: ["https://www.googleapis.com/auth/cloud-platform"]
    });
  });
});

afterEach(() => {
  nock.cleanAll();
  sandbox.restore();
});


it('should refresh if access token has expired', async () => {
  const scopes = [mockExample()];
  impersonated.credentials.access_token = 'initial-access-token';
  impersonated.credentials.expiry_date = new Date().getTime() - 10000;
  await impersonated.request({ url });
  assert.strictEqual(impersonated.credentials.access_token, 'abc123');
  scopes.forEach(s => s.done());
});

