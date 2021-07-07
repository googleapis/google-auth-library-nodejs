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
import * as nock from 'nock';
import {describe, it, afterEach} from 'mocha';
import {Impersonated, JWT} from '../src';
import {CredentialRequest} from '../src/auth/credentials';

const PEM_PATH = './test/fixtures/private.pem';

nock.disableNetConnect();

const url = 'http://example.com';

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, body);
}

describe('impersonated', () => {
  afterEach(() => {
    nock.cleanAll();
  });
  it('should request impersonated credentials on first request');
  it.only('should refresh if access token has expired', async () => {
    const scopes = [
      nock(url).get('/').reply(200),
      createGTokenMock({
        access_token: 'abc123',
      }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    await jwt.authorize();
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    impersonated.credentials.access_token = 'initial-access-token';
    impersonated.credentials.expiry_date = Date.now() - 10000;
    await impersonated.request({url});
    assert.strictEqual(impersonated.credentials.access_token, 'abc123');
    scopes.forEach(s => s.done());
  });
  it(
    'should throw appropriate exception when 403 occurs refreshing impersonated credentials'
  );
  it('should throw appropriate exception when 403 occurs during request');
});
