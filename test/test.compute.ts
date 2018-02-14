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
import {BASE_PATH, HOST_ADDRESS} from 'gcp-metadata';
import * as nock from 'nock';

import {Credentials} from '../src/auth/credentials';
import {Compute} from '../src/index';

nock.disableNetConnect();

const tokenPath = `${BASE_PATH}/instance/service-accounts/default/token`;

describe('Initial credentials', () => {
  it('should create a dummy refresh token string', () => {
    // It is important that the compute client is created with a refresh token
    // value filled in, or else the rest of the logic will not work.
    const compute = new Compute();
    assert.equal('compute-placeholder', compute.credentials.refresh_token);
  });
});

describe('Compute auth client', () => {
  afterEach(() => {
    nock.cleanAll();
  });

  // set up compute client.
  let compute: Compute;
  beforeEach(() => {
    compute = new Compute();
  });

  it('should get an access token for the first request', done => {
    nock(HOST_ADDRESS).get(tokenPath).reply(200, {
      access_token: 'abc123',
      expires_in: 10000
    });
    compute.request({url: 'http://foo'}, () => {
      assert.equal(compute.credentials.access_token, 'abc123');
      done();
    });
  });

  it('should refresh if access token has expired', (done) => {
    nock(HOST_ADDRESS).get(tokenPath).reply(200, {
      access_token: 'abc123',
      expires_in: 10000
    });
    compute.credentials.access_token = 'initial-access-token';
    compute.credentials.expiry_date = (new Date()).getTime() - 10000;
    compute.request({url: 'http://foo'}, () => {
      assert.equal(compute.credentials.access_token, 'abc123');
      done();
    });
  });

  it('should refresh if access token will expired soon and time to refresh' +
         ' before expiration is set',
     (done) => {
       nock(HOST_ADDRESS).get(tokenPath).reply(200, {
         access_token: 'abc123',
         expires_in: 10000
       });
       compute = new Compute({eagerRefreshThresholdMillis: 10000});
       compute.credentials.access_token = 'initial-access-token';
       compute.credentials.expiry_date = (new Date()).getTime() + 5000;
       compute.request({url: 'http://foo'}, () => {
         assert.equal(compute.credentials.access_token, 'abc123');
         done();
       });
     });

  it('should not refresh if access token will not expire soon and time to' +
         ' refresh before expiration is set',
     (done) => {
       const scope = nock(HOST_ADDRESS).get(tokenPath).reply(200, {
         access_token: 'abc123',
         expires_in: 10000
       });
       compute = new Compute({eagerRefreshThresholdMillis: 1000});
       compute.credentials.access_token = 'initial-access-token';
       compute.credentials.expiry_date = (new Date()).getTime() + 12000;
       compute.request({url: 'http://foo'}, () => {
         assert.equal(compute.credentials.access_token, 'initial-access-token');
         assert.equal(false, scope.isDone());
         nock.cleanAll();
         done();
       });
     });

  it('should not refresh if access token has not expired', (done) => {
    const scope = nock(HOST_ADDRESS).get(tokenPath).reply(200, {
      access_token: 'abc123',
      expires_in: 10000
    });
    compute.credentials.access_token = 'initial-access-token';
    compute.credentials.expiry_date = (new Date()).getTime() + 10 * 60 * 1000;
    compute.request({url: 'http://foo'}, () => {
      assert.equal(compute.credentials.access_token, 'initial-access-token');
      assert.equal(false, scope.isDone());
      nock.cleanAll();
      done();
    });
  });

  it('should retry calls to the metadata service if there are network errors',
     (done) => {
       const scope =
           nock(HOST_ADDRESS)
               .get(tokenPath)
               .times(2)
               .replyWithError({code: 'ENOTFOUND'})
               .get(tokenPath)
               .reply(200, {access_token: 'abc123', expires_in: 10000});
       compute.credentials.access_token = 'initial-access-token';
       compute.credentials.expiry_date = (new Date()).getTime() - 10000;
       compute.request({url: 'http://foo'}, e => {
         assert.equal(compute.credentials.access_token, 'abc123');
         scope.done();
         done();
       });
     });

  it('should retry calls to the metadata service if it returns non-200 errors',
     (done) => {
       const scope =
           nock(HOST_ADDRESS)
               .get(tokenPath)
               .times(2)
               .reply(500)
               .get(tokenPath)
               .reply(200, {access_token: 'abc123', expires_in: 10000});
       compute.credentials.access_token = 'initial-access-token';
       compute.credentials.expiry_date = (new Date()).getTime() - 10000;
       compute.request({url: 'http://foo'}, e => {
         assert.equal(compute.credentials.access_token, 'abc123');
         scope.done();
         done();
       });
     });

  describe('.createScopedRequired', () => {
    it('should return false', () => {
      const c = new Compute();
      assert.equal(false, c.createScopedRequired());
    });
  });

  describe('._injectErrorMessage', () => {
    it('should return a helpful message on request response.statusCode 403', done => {
      // Mock the credentials object.
      compute.credentials = {
        refresh_token: 'hello',
        access_token: 'goodbye',
        expiry_date: (new Date(9999, 1, 1)).getTime()
      };

      nock('http://foo').get('/').twice().reply(403, 'a weird response body');
      nock(HOST_ADDRESS).get(tokenPath).reply(403, 'a weird response body');

      compute.request({url: 'http://foo'}, (err, response) => {
        assert(response);
        assert.equal(403, response ? response.status : 0);
        const expected =
            'A Forbidden error was returned while attempting to retrieve an access ' +
            'token for the Compute Engine built-in service account. This may be because the ' +
            'Compute Engine instance does not have the correct permission scopes specified. ' +
            'Could not refresh access token.';
        assert.equal(expected, err ? err.message : null);
        done();
      });
    });

    it('should return a helpful message on request response.statusCode 404',
       (done) => {
         // Mock the credentials object.
         compute.credentials = {
           refresh_token: 'hello',
           access_token: 'goodbye',
           expiry_date: (new Date(9999, 1, 1)).getTime()
         };

         // Mock the request method to return a 404.
         nock('http://foo')
             .get('/')
             .twice()
             .reply(404, 'a weird response body');

         compute.request({url: 'http://foo'}, (err, response) => {
           assert.equal(404, response ? response.status : 0);
           assert.equal(
               'A Not Found error was returned while attempting to retrieve an access' +
                   'token for the Compute Engine built-in service account. This may be because the ' +
                   'Compute Engine instance does not have any permission scopes specified. ' +
                   'a weird response body',
               err ? err.message : null);
           done();
         });
       });

    it('should return a helpful message on token refresh response.statusCode 403',
       (done) => {
         nock(HOST_ADDRESS)
             .get(tokenPath)
             .twice()
             .reply(403, 'a weird response body');

         // Mock the credentials object with a null access token, to force
         // a refresh.
         compute.credentials = {
           refresh_token: 'hello',
           access_token: undefined,
           expiry_date: 1
         };

         compute.request({}, (err, response) => {
           assert.equal(403, response ? response.status : null);
           const expected =
               'A Forbidden error was returned while attempting to retrieve an access ' +
               'token for the Compute Engine built-in service account. This may be because the ' +
               'Compute Engine instance does not have the correct permission scopes specified. ' +
               'Could not refresh access token.';
           assert.equal(expected, err ? err.message : null);
           nock.cleanAll();
           done();
         });
       });

    it('should return a helpful message on token refresh response.statusCode 404',
       done => {
         nock(HOST_ADDRESS).get(tokenPath).reply(404, 'a weird body');

         // Mock the credentials object with a null access token, to force
         // a refresh.
         compute.credentials = {
           refresh_token: 'hello',
           access_token: undefined,
           expiry_date: 1
         } as Credentials;

         compute.request({}, (err, response) => {
           assert.equal(404, response ? response.status : null);
           assert.equal(
               'A Not Found error was returned while attempting to retrieve an access' +
                   'token for the Compute Engine built-in service account. This may be because the ' +
                   'Compute Engine instance does not have any permission scopes specified. Could not ' +
                   'refresh access token.',
               err ? err.message : null);
           done();
         });
       });
  });
});
