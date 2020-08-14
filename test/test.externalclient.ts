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
import {describe, it, afterEach} from 'mocha';
import * as qs from 'querystring';
import * as nock from 'nock';
import * as sinon from 'sinon';
import {createCrypto} from '../src/crypto/crypto';
import {Credentials} from '../src/auth/credentials';
import {StsSuccessfulResponse} from '../src/auth/stscredentials';
import {
  EXPIRATION_TIME_OFFSET,
  ExternalAccountClient,
} from '../src/auth/externalclient';
import {
  OAuthErrorResponse,
  getErrorFromOAuthErrorResponse,
} from '../src/auth/oauth2common';
import {GetAccessTokenResponse} from '../src/auth/oauth2client';
import {GaxiosError} from 'gaxios';

nock.disableNetConnect();

interface NockMockStsToken {
  statusCode: number;
  response: StsSuccessfulResponse | OAuthErrorResponse;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request: {[key: string]: any};
  additionalHeaders?: {[key: string]: string};
}

interface SampleResponse {
  foo: string;
  bar: number;
}

/** Test class to test abstract class ExternalAccountClient. */
class TestExternalAccountClient extends ExternalAccountClient {
  private counter = 0;

  async retrieveSubjectToken(): Promise<string> {
    // Increment subject_token counter each time this is called.
    return `subject_token_${this.counter++}`;
  }
}

describe('ExternalAccountClient', () => {
  let clock: sinon.SinonFakeTimers;
  const ONE_HOUR_IN_SECS = 3600;
  const crypto = createCrypto();
  const baseUrl = 'https://sts.googleapis.com';
  const path = '/v1/token';
  const projectNumber = '123456';
  const poolId = 'POOL_ID';
  const providerId = 'PROVIDER_ID';
  const audience =
    `//iam.googleapis.com/project/${projectNumber}` +
    `/locations/global/workloadIdentityPools/${poolId}/` +
    `providers/${providerId}`;
  const externalAccountOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: `${baseUrl}${path}`,
    credential_source: {
      file: '/var/run/secrets/goog.id/token',
    },
  };
  const externalAccountOptionsWithCreds = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: `${baseUrl}${path}`,
    credential_source: {
      file: '/var/run/secrets/goog.id/token',
    },
    client_id: 'CLIENT_ID',
    client_secret: 'SECRET',
  };
  const basicAuthCreds =
    `${externalAccountOptionsWithCreds.client_id}:` +
    `${externalAccountOptionsWithCreds.client_secret}`;
  const stsSuccessfulResponse: StsSuccessfulResponse = {
    access_token: 'ACCESS_TOKEN',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: ONE_HOUR_IN_SECS,
    scope: 'scope1 scope2',
  };

  function assertGaxiosResponsePresent(resp: GetAccessTokenResponse) {
    const gaxiosResponse = resp.res || {};
    assert('data' in gaxiosResponse && 'status' in gaxiosResponse);
  }

  function mockStsTokenExchange(nockParams: NockMockStsToken[]): nock.Scope {
    const scope = nock(baseUrl);
    nockParams.forEach(nockMockStsToken => {
      const headers = Object.assign(
        {
          'content-type': 'application/x-www-form-urlencoded',
        },
        nockMockStsToken.additionalHeaders || {}
      );
      scope
        .post(path, qs.stringify(nockMockStsToken.request), {
          reqheaders: headers,
        })
        .reply(nockMockStsToken.statusCode, nockMockStsToken.response);
    });
    return scope;
  }

  afterEach(() => {
    nock.cleanAll();
    if (clock) {
      clock.restore();
    }
  });

  describe('Constructor', () => {
    it('should throw on invalid type', () => {
      const expectedError = new Error(
        'Expected "external_account" type but received "invalid"'
      );
      const invalidOptions = Object.assign({}, externalAccountOptions);
      invalidOptions.type = 'invalid';

      assert.throws(() => {
        return new TestExternalAccountClient(invalidOptions);
      }, expectedError);
    });

    it('should not throw on valid options', () => {
      assert.doesNotThrow(() => {
        return new TestExternalAccountClient(externalAccountOptions);
      });
    });
  });

  describe('getAccessToken()', () => {
    it('should resolve with the expected GetAccessTokenResponse', async () => {
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      const actualResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });
      scope.done();
    });

    it('should handle underlying token exchange errors', async () => {
      const errorResponse: OAuthErrorResponse = {
        error: 'invalid_request',
        error_description: 'Invalid subject token',
        error_uri: 'https://tools.ietf.org/html/rfc6749#section-5.2',
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_1',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      await assert.rejects(
        client.getAccessToken(),
        getErrorFromOAuthErrorResponse(errorResponse)
      );
      // Next try should succeed.
      const actualResponse = await client.getAccessToken();
      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });
      scope.done();
    });

    it('should use explicit scopes array when provided', async () => {
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'scope1 scope2',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.scopes = ['scope1', 'scope2'];
      const actualResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });
      scope.done();
    });

    it('should use explicit scopes string when provided', async () => {
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'scope1',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.scopes = 'scope1';
      const actualResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });
      scope.done();
    });

    it('should force refresh when cached credential is expired', async () => {
      clock = sinon.useFakeTimers(0);
      const emittedEvents: Credentials[] = [];
      const stsSuccessfulResponse2 = Object.assign({}, stsSuccessfulResponse);
      stsSuccessfulResponse2.access_token = 'ACCESS_TOKEN2';
      // Use different expiration time for second token to confirm tokens event
      // calculates the credentials expiry_date correctly.
      stsSuccessfulResponse2.expires_in = 1600;
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
        {
          statusCode: 200,
          response: stsSuccessfulResponse2,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_1',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      // Listen to tokens events. On every event, push to list of emittedEvents.
      client.on('tokens', tokens => {
        emittedEvents.push(tokens);
      });
      const actualResponse = await client.getAccessToken();

      // tokens event should be triggered once with expected event.
      assert.strictEqual(emittedEvents.length, 1);
      assert.deepStrictEqual(emittedEvents[0], {
        refresh_token: null,
        expiry_date: new Date().getTime() + ONE_HOUR_IN_SECS * 1000,
        access_token: stsSuccessfulResponse.access_token,
        token_type: 'Bearer',
        id_token: null,
      });
      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });

      // Try again. Cached credential should be returned.
      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const actualCachedResponse = await client.getAccessToken();

      // No new event should be triggered since the cached access token is
      // returned.
      assert.strictEqual(emittedEvents.length, 1);
      delete actualCachedResponse.res;
      assert.deepStrictEqual(actualCachedResponse, {
        token: stsSuccessfulResponse.access_token,
      });

      // Simulate credential is expired.
      clock.tick(1);
      const actualNewCredResponse = await client.getAccessToken();

      // tokens event should be triggered again with the expected event.
      assert.strictEqual(emittedEvents.length, 2);
      assert.deepStrictEqual(emittedEvents[1], {
        refresh_token: null,
        // Second expiration time should be used.
        expiry_date:
          new Date().getTime() + stsSuccessfulResponse2.expires_in * 1000,
        access_token: stsSuccessfulResponse2.access_token,
        token_type: 'Bearer',
        id_token: null,
      });
      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualNewCredResponse);
      delete actualNewCredResponse.res;
      assert.deepStrictEqual(actualNewCredResponse, {
        token: stsSuccessfulResponse2.access_token,
      });

      scope.done();
    });

    it('should respect eagerRefreshThresholdMillis when provided', async () => {
      clock = sinon.useFakeTimers(0);
      const customThresh = 10 * 1000;
      const stsSuccessfulResponse2 = Object.assign({}, stsSuccessfulResponse);
      stsSuccessfulResponse2.access_token = 'ACCESS_TOKEN2';
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
        {
          statusCode: 200,
          response: stsSuccessfulResponse2,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_1',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions, {
        // Override 5min threshold with 10 second threshold.
        eagerRefreshThresholdMillis: customThresh,
      });
      const actualResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });

      // Try again. Cached credential should be returned.
      clock.tick(ONE_HOUR_IN_SECS * 1000 - customThresh - 1);
      const actualCachedResponse = await client.getAccessToken();

      delete actualCachedResponse.res;
      assert.deepStrictEqual(actualCachedResponse, {
        token: stsSuccessfulResponse.access_token,
      });

      // Simulate credential is expired.
      // As current time is equal to expirationTime - customThresh,
      // refresh should be triggered.
      clock.tick(1);
      const actualNewCredResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualNewCredResponse);
      delete actualNewCredResponse.res;
      assert.deepStrictEqual(actualNewCredResponse, {
        token: stsSuccessfulResponse2.access_token,
      });

      scope.done();
    });

    it('should apply basic auth when client_id/secret are provided', async () => {
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
          additionalHeaders: {
            Authorization: `Basic ${crypto.encodeBase64StringUtf8(
              basicAuthCreds
            )}`,
          },
        },
      ]);

      const client = new TestExternalAccountClient(
        externalAccountOptionsWithCreds
      );
      const actualResponse = await client.getAccessToken();

      // Confirm raw GaxiosResponse appended to response.
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: stsSuccessfulResponse.access_token,
      });
      scope.done();
    });
  });

  describe('getRequestHeaders()', () => {
    it('should inject the authorization headers', async () => {
      const expectedHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      const actualHeaders = await client.getRequestHeaders();

      assert.deepStrictEqual(actualHeaders, expectedHeaders);
      scope.done();
    });

    it('should inject the authorization and metadata headers', async () => {
      const quotaProjectId = 'QUOTA_PROJECT_ID';
      const expectedHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
        'x-goog-user-project': quotaProjectId,
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const optionsWithQuotaProjectId = Object.assign(
        {quota_project_id: quotaProjectId},
        externalAccountOptions
      );
      const client = new TestExternalAccountClient(optionsWithQuotaProjectId);
      const actualHeaders = await client.getRequestHeaders();

      assert.deepStrictEqual(expectedHeaders, actualHeaders);
      scope.done();
    });

    it('should reject when error occurs during token retrieval', async () => {
      const errorResponse: OAuthErrorResponse = {
        error: 'invalid_request',
        error_description: 'Invalid subject token',
        error_uri: 'https://tools.ietf.org/html/rfc6749#section-5.2',
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      await assert.rejects(
        client.getRequestHeaders(),
        getErrorFromOAuthErrorResponse(errorResponse)
      );
      scope.done();
    });
  });

  describe('request()', () => {
    it('should process HTTP request with authorization header', async () => {
      const quotaProjectId = 'QUOTA_PROJECT_ID';
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
        'x-goog-user-project': quotaProjectId,
      };
      const optionsWithQuotaProjectId = Object.assign(
        {quota_project_id: quotaProjectId},
        externalAccountOptions
      );
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse: SampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new TestExternalAccountClient(optionsWithQuotaProjectId);
      const actualResponse = await client.request<SampleResponse>({
        url: 'https://example.com/api',
        method: 'POST',
        headers: exampleHeaders,
        data: exampleRequest,
        responseType: 'json',
      });

      assert.deepStrictEqual(actualResponse.data, exampleResponse);
      scopes.forEach(scope => scope.done());
    });

    it('should process headerless HTTP request', async () => {
      const quotaProjectId = 'QUOTA_PROJECT_ID';
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
        'x-goog-user-project': quotaProjectId,
      };
      const optionsWithQuotaProjectId = Object.assign(
        {quota_project_id: quotaProjectId},
        externalAccountOptions
      );
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse: SampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new TestExternalAccountClient(optionsWithQuotaProjectId);
      // Send request with no headers.
      const actualResponse = await client.request<SampleResponse>({
        url: 'https://example.com/api',
        method: 'POST',
        data: exampleRequest,
        responseType: 'json',
      });

      assert.deepStrictEqual(actualResponse.data, exampleResponse);
      scopes.forEach(scope => scope.done());
    });

    it('should reject when error occurs during token retrieval', async () => {
      const errorResponse: OAuthErrorResponse = {
        error: 'invalid_request',
        error_description: 'Invalid subject token',
        error_uri: 'https://tools.ietf.org/html/rfc6749#section-5.2',
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      await assert.rejects(
        client.request<SampleResponse>({
          url: 'https://example.com/api',
          method: 'POST',
          data: exampleRequest,
          responseType: 'json',
        }),
        getErrorFromOAuthErrorResponse(errorResponse)
      );
      scope.done();
    });

    it('should trigger callback on success when provided', done => {
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse: SampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.request<SampleResponse>(
        {
          url: 'https://example.com/api',
          method: 'POST',
          headers: exampleHeaders,
          data: exampleRequest,
          responseType: 'json',
        },
        (err, result) => {
          assert.strictEqual(err, null);
          assert.deepStrictEqual(result?.data, exampleResponse);
          scopes.forEach(scope => scope.done());
          done();
        }
      );
    });

    it('should trigger callback on error when provided', done => {
      const errorMessage = 'Bad Request';
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(400, errorMessage),
      ];

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.request<SampleResponse>(
        {
          url: 'https://example.com/api',
          method: 'POST',
          headers: exampleHeaders,
          data: exampleRequest,
          responseType: 'json',
        },
        (err, result) => {
          assert.strictEqual(err!.message, errorMessage);
          assert.deepStrictEqual(result, (err as GaxiosError)!.response);
          scopes.forEach(scope => scope.done());
          done();
        }
      );
    });

    it('should retry on 401 on forceRefreshOnFailure=true', async () => {
      const stsSuccessfulResponse2 = Object.assign({}, stsSuccessfulResponse);
      stsSuccessfulResponse2.access_token = 'ACCESS_TOKEN2';
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const authHeaders2 = {
        Authorization: `Bearer ${stsSuccessfulResponse2.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse: SampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
          {
            statusCode: 200,
            response: stsSuccessfulResponse2,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_1',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(401)
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders2),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new TestExternalAccountClient(externalAccountOptions, {
        forceRefreshOnFailure: true,
      });
      const actualResponse = await client.request<SampleResponse>({
        url: 'https://example.com/api',
        method: 'POST',
        headers: exampleHeaders,
        data: exampleRequest,
        responseType: 'json',
      });

      assert.deepStrictEqual(actualResponse.data, exampleResponse);
      scopes.forEach(scope => scope.done());
    });

    it('should not retry on 401 on forceRefreshOnFailure=false', async () => {
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(401),
      ];

      const client = new TestExternalAccountClient(externalAccountOptions);
      await assert.rejects(
        client.request<SampleResponse>({
          url: 'https://example.com/api',
          method: 'POST',
          headers: exampleHeaders,
          data: exampleRequest,
          responseType: 'json',
        }),
        {
          code: '401',
        }
      );

      scopes.forEach(scope => scope.done());
    });

    it('should not retry more than once', async () => {
      const stsSuccessfulResponse2 = Object.assign({}, stsSuccessfulResponse);
      stsSuccessfulResponse2.access_token = 'ACCESS_TOKEN2';
      const authHeaders = {
        Authorization: `Bearer ${stsSuccessfulResponse.access_token}`,
      };
      const authHeaders2 = {
        Authorization: `Bearer ${stsSuccessfulResponse2.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_0',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
          {
            statusCode: 200,
            response: stsSuccessfulResponse2,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience,
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: 'subject_token_1',
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(403)
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders2),
          })
          .reply(403),
      ];

      const client = new TestExternalAccountClient(externalAccountOptions, {
        forceRefreshOnFailure: true,
      });
      await assert.rejects(
        client.request<SampleResponse>({
          url: 'https://example.com/api',
          method: 'POST',
          headers: exampleHeaders,
          data: exampleRequest,
          responseType: 'json',
        }),
        {
          code: '403',
        }
      );

      scopes.forEach(scope => scope.done());
    });
  });

  describe('setCredentials()', () => {
    it('should allow injection of GCP access tokens directly', async () => {
      clock = sinon.useFakeTimers(0);
      const credentials = {
        access_token: 'INJECTED_ACCESS_TOKEN',
        // Simulate token expires in 10mins.
        expiry_date: new Date().getTime() + 10 * 60 * 1000,
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            audience,
            scope: 'https://www.googleapis.com/auth/cloud-platform',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          },
        },
      ]);

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.setCredentials(credentials);

      clock.tick(10 * 60 * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const tokenResponse = await client.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);

      // Simulate token expired.
      clock.tick(1);
      const refreshedTokenResponse = await client.getAccessToken();
      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        stsSuccessfulResponse.access_token
      );

      scope.done();
    });

    it('should not expire injected creds with no expiry_date', async () => {
      clock = sinon.useFakeTimers(0);
      const credentials = {
        access_token: 'INJECTED_ACCESS_TOKEN',
      };

      const client = new TestExternalAccountClient(externalAccountOptions);
      client.setCredentials(credentials);

      const tokenResponse = await client.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);

      clock.tick(ONE_HOUR_IN_SECS);
      const unexpiredTokenResponse = await client.getAccessToken();
      assert.deepStrictEqual(
        unexpiredTokenResponse.token,
        credentials.access_token
      );
    });
  });
});
