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
import {AxiosError} from 'axios';
import {BASE_PATH, HEADERS, HOST_ADDRESS} from 'gcp-metadata';
import * as nock from 'nock';

import {Compute} from '../src';

nock.disableNetConnect();

const url = 'http://example.com';

const tokenPath = `${BASE_PATH}/instance/service-accounts/default/token`;
function mockToken() {
  return nock(HOST_ADDRESS)
      .get(tokenPath)
      .reply(200, {access_token: 'abc123', expires_in: 10000}, HEADERS);
}

function mockExample() {
  return nock(url).get('/').reply(200);
}

// set up compute client.
let compute: Compute;
beforeEach(() => {
  compute = new Compute();
});

afterEach(() => {
  nock.cleanAll();
});

it('should create a dummy refresh token string', () => {
  // It is important that the compute client is created with a refresh token
  // value filled in, or else the rest of the logic will not work.
  const compute = new Compute();
  assert.equal('compute-placeholder', compute.credentials.refresh_token);
});

it('should get an access token for the first request', async () => {
  const scopes = [mockToken(), mockExample()];
  await compute.request({url});
  scopes.forEach(s => s.done());
  assert.equal(compute.credentials.access_token, 'abc123');
});

it('should refresh if access token has expired', async () => {
  const scopes = [mockToken(), mockExample()];
  compute.credentials.access_token = 'initial-access-token';
  compute.credentials.expiry_date = (new Date()).getTime() - 10000;
  await compute.request({url});
  assert.equal(compute.credentials.access_token, 'abc123');
  scopes.forEach(s => s.done());
});

it('should refresh if access token will expired soon and time to refresh before expiration is set',
   async () => {
     const scopes = [mockToken(), mockExample()];
     compute = new Compute({eagerRefreshThresholdMillis: 10000});
     compute.credentials.access_token = 'initial-access-token';
     compute.credentials.expiry_date = (new Date()).getTime() + 5000;
     await compute.request({url});
     assert.equal(compute.credentials.access_token, 'abc123');
     scopes.forEach(s => s.done());
   });

it('should not refresh if access token will not expire soon and time to refresh before expiration is set',
   async () => {
     const scope = mockExample();
     compute = new Compute({eagerRefreshThresholdMillis: 1000});
     compute.credentials.access_token = 'initial-access-token';
     compute.credentials.expiry_date = (new Date()).getTime() + 12000;
     await compute.request({url});
     assert.equal(compute.credentials.access_token, 'initial-access-token');
     scope.done();
   });

it('should not refresh if access token has not expired', async () => {
  const scope = mockExample();
  compute.credentials.access_token = 'initial-access-token';
  compute.credentials.expiry_date = (new Date()).getTime() + 10 * 60 * 1000;
  await compute.request({url});
  assert.equal(compute.credentials.access_token, 'initial-access-token');
  scope.done();
});

it('should retry calls to the metadata service if there are network errors',
   async () => {
     const scopes = [
       nock(HOST_ADDRESS)
           .get(tokenPath)
           .times(2)
           .replyWithError({code: 'ENOTFOUND'})
           .get(tokenPath)
           .reply(200, {access_token: 'abc123', expires_in: 10000}, HEADERS),
       mockExample()
     ];
     compute.credentials.access_token = 'initial-access-token';
     compute.credentials.expiry_date = (new Date()).getTime() - 10000;
     await compute.request({url});
     assert.equal(compute.credentials.access_token, 'abc123');
     scopes.forEach(s => s.done());
   });

it('should retry calls to the metadata service if it returns non-200 errors',
   async () => {
     const scopes = [
       nock(HOST_ADDRESS)
           .get(tokenPath)
           .times(2)
           .reply(500)
           .get(tokenPath)
           .reply(200, {access_token: 'abc123', expires_in: 10000}, HEADERS),
       mockExample()
     ];
     compute.credentials.access_token = 'initial-access-token';
     compute.credentials.expiry_date = (new Date()).getTime() - 10000;
     await compute.request({url});
     assert.equal(compute.credentials.access_token, 'abc123');
     scopes.forEach(s => s.done());
   });

it('should return a helpful message on request response.statusCode 403',
   async () => {
     // Mock the credentials object.  Make sure there's no expiry_date set.
     compute.credentials = {
       refresh_token: 'hello',
       access_token: 'goodbye',
     };

     const scopes = [
       nock(url).get('/').reply(403),
       nock(HOST_ADDRESS).get(tokenPath).reply(403, HEADERS)
     ];

     try {
       await compute.request({url});
     } catch (e) {
       scopes.forEach(s => s.done());
       const err = e as AxiosError;
       assert.equal(403, err.response!.status);
       assert(err.message.startsWith('A Forbidden error was returned'));
       return;
     }
     throw new Error('Expected to throw');
   });

it('should return a helpful message on request response.statusCode 404', async () => {
  // Mock the credentials object.
  compute.credentials = {
    refresh_token: 'hello',
    access_token: 'goodbye',
    expiry_date: (new Date(9999, 1, 1)).getTime()
  };
  // Mock the request method to return a 404.
  const scope = nock(url).get('/').reply(404);
  try {
    await compute.request({url});
  } catch (e) {
    scope.done();
    const err = e as AxiosError;
    assert.equal(404, e.response!.status);
    assert.equal(
        'A Not Found error was returned while attempting to retrieve an access' +
            'token for the Compute Engine built-in service account. This may be because the ' +
            'Compute Engine instance does not have any permission scopes specified.',
        err.message);
    return;
  }
  throw new Error('Expected to throw');
});

it('should return a helpful message on token refresh response.statusCode 403',
   async () => {
     const scope = nock(HOST_ADDRESS).get(tokenPath).twice().reply(403);
     // Mock the credentials object with a null access token, to force a
     // refresh.
     compute.credentials = {
       refresh_token: 'hello',
       access_token: undefined,
       expiry_date: 1
     };
     try {
       await compute.request({});
     } catch (e) {
       const err = e as AxiosError;
       assert.equal(403, err.response!.status);
       const expected =
           'A Forbidden error was returned while attempting to retrieve an access ' +
           'token for the Compute Engine built-in service account. This may be because the ' +
           'Compute Engine instance does not have the correct permission scopes specified. ' +
           'Could not refresh access token.';
       assert.equal(expected, err.message);
       return;
     }
     throw new Error('Expected to throw');
   });

it('should return a helpful message on token refresh response.statusCode 404',
   async () => {
     const scope = nock(HOST_ADDRESS).get(tokenPath).reply(404);

     // Mock the credentials object with a null access token, to force
     // a refresh.
     compute.credentials = {
       refresh_token: 'hello',
       access_token: undefined,
       expiry_date: 1
     };

     try {
       await compute.request({});
     } catch (e) {
       const err = e as AxiosError;
       assert.equal(404, e.response!.status);
       assert.equal(
           'A Not Found error was returned while attempting to retrieve an access' +
               'token for the Compute Engine built-in service account. This may be because the ' +
               'Compute Engine instance does not have any permission scopes specified. Could not ' +
               'refresh access token.',
           err.message);
       return;
     }
     throw new Error('Expected to throw');
   });
