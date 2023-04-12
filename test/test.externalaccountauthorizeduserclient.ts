// Copyright 2023 Google LLC
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
import {describe, it, afterEach, beforeEach} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';
import * as qs from 'querystring';
import {assertGaxiosResponsePresent, getAudience} from './externalclienthelper';
import {
  EXTERNAL_ACCOUNT_AUTHORIZED_USER_TYPE,
  ExternalAccountAuthorizedUserClient,
  ExternalAccountAuthorizedUserClientOptions,
} from '../src/auth/externalAccountAuthorizedUserClient';
import {EXPIRATION_TIME_OFFSET} from '../src/auth/baseexternalclient';
import {GaxiosError, GaxiosResponse} from 'gaxios';
import {
  getErrorFromOAuthErrorResponse,
  OAuthErrorResponse,
} from '../src/auth/oauth2common';

nock.disableNetConnect();

describe('ExternalAccountAuthorizedUserClient', () => {
  const BASE_URL = 'https://sts.googleapis.com';
  const REFRESH_PATH = '/v1/oauthtoken';
  const TOKEN_REFRESH_URL = `${BASE_URL}${REFRESH_PATH}`;
  const TOKEN_INFO_URL = `${BASE_URL}/v1/introspect`;

  interface TokenRefreshResponse {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    res?: GaxiosResponse | null;
  }

  interface NockMockRefreshResponse {
    statusCode: number;
    response: TokenRefreshResponse | OAuthErrorResponse;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    request: {[key: string]: any};
    times?: number;
    additionalHeaders?: {[key: string]: string};
  }

  function mockStsTokenRefresh(
    url: string,
    path: string,
    nockParams: NockMockRefreshResponse[]
  ): nock.Scope {
    const scope = nock(url);
    nockParams.forEach(nockMockStsToken => {
      const times =
        nockMockStsToken.times !== undefined ? nockMockStsToken.times : 1;
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
        .times(times)
        .reply(nockMockStsToken.statusCode, nockMockStsToken.response);
    });
    return scope;
  }

  let clock: sinon.SinonFakeTimers;
  const referenceDate = new Date('2020-08-11T06:55:22.345Z');
  const audience = getAudience();
  const externalAccountAuthorizedUserCredentialOptions = {
    type: EXTERNAL_ACCOUNT_AUTHORIZED_USER_TYPE,
    audience: audience,
    client_id: 'clientId',
    client_secret: 'clientSecret',
    refresh_token: 'refreshToken',
    token_url: TOKEN_REFRESH_URL,
    token_info_url: TOKEN_INFO_URL,
  } as ExternalAccountAuthorizedUserClientOptions;
  const successfulRefreshResponse = {
    access_token: 'newAccessToken',
    refresh_token: 'newRefreshToken',
    expires_in: 3600,
  };
  const successfulRefreshResponseNoRefreshToken = {
    access_token: 'newAccessToken',
    expires_in: 3600,
  };
  beforeEach(() => {
    clock = sinon.useFakeTimers(referenceDate);
  });

  afterEach(() => {
    if (clock) {
      clock.restore();
    }
  });

  describe('Constructor', () => {
    it('should not throw when valid options are provided', () => {
      assert.doesNotThrow(() => {
        return new ExternalAccountAuthorizedUserClient(
          externalAccountAuthorizedUserCredentialOptions
        );
      });
    });

    it('should set default RefreshOptions', () => {
      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );

      assert(!client.forceRefreshOnFailure);
      assert(client.eagerRefreshThresholdMillis === EXPIRATION_TIME_OFFSET);
    });

    it('should set custom RefreshOptions', () => {
      const refreshOptions = {
        eagerRefreshThresholdMillis: 5000,
        forceRefreshOnFailure: true,
      };
      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions,
        refreshOptions
      );

      assert.strictEqual(
        client.forceRefreshOnFailure,
        refreshOptions.forceRefreshOnFailure
      );
      assert.strictEqual(
        client.eagerRefreshThresholdMillis,
        refreshOptions.eagerRefreshThresholdMillis
      );
    });
  });

  describe('getAccessToken()', () => {
    it('should resolve with the expected response', async () => {
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 200,
          response: successfulRefreshResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      const actualResponse = await client.getAccessToken();
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: successfulRefreshResponse.access_token,
      });
      scope.done();
    });

    it('should handle refresh errors', async () => {
      const errorResponse: OAuthErrorResponse = {
        error: 'invalid_request',
        error_description: 'Invalid refresh token',
        error_uri: 'https://tools.ietf.org/html/rfc6749#section-5.2',
      };

      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      await assert.rejects(
        client.getAccessToken(),
        getErrorFromOAuthErrorResponse(errorResponse)
      );
      scope.done();
    });

    it('should handle refresh timeout', async () => {
      const expectedRequest = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'refreshToken',
      });

      const scope = nock(BASE_URL)
        .post(REFRESH_PATH, expectedRequest.toString(), {
          reqheaders: {
            'content-type': 'application/x-www-form-urlencoded',
          },
        })
        .replyWithError({code: 'ETIMEDOUT'});

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      await assert.rejects(client.getAccessToken(), {
        code: 'ETIMEDOUT',
      });
      scope.done();
    });

    it('should use the new refresh token', async () => {
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 200,
          response: successfulRefreshResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token:
              externalAccountAuthorizedUserCredentialOptions.refresh_token,
          },
        },
        {
          statusCode: 200,
          response: successfulRefreshResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token: successfulRefreshResponse.refresh_token,
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      // Get initial access token and new refresh token.
      await client.getAccessToken();
      // Advance clock to force new refresh.
      clock.tick((successfulRefreshResponse.expires_in + 1) * 1000);
      // Refresh access token with new access token.
      const actualResponse = await client.getAccessToken();
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: successfulRefreshResponse.access_token,
      });

      scope.done();
    });

    it('should not call refresh when token is cached', async () => {
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 200,
          response: successfulRefreshResponseNoRefreshToken,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      // Get initial access token and new refresh token.
      await client.getAccessToken();
      // Advance clock to force new refresh.
      clock.tick(
        successfulRefreshResponseNoRefreshToken.expires_in * 1000 -
          client.eagerRefreshThresholdMillis -
          1
      );
      // Refresh access token with new access token.
      const actualResponse = await client.getAccessToken();
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: successfulRefreshResponse.access_token,
      });

      scope.done();
    });

    it('should refresh when cached token is expired', async () => {
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 200,
          response: successfulRefreshResponseNoRefreshToken,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
          times: 2,
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      // Get initial access token.
      await client.getAccessToken();
      // Advance clock to force new refresh.
      clock.tick(
        successfulRefreshResponseNoRefreshToken.expires_in * 1000 -
          client.eagerRefreshThresholdMillis +
          1
      );
      // Refresh access token with new access token.
      const actualResponse = await client.getAccessToken();
      assertGaxiosResponsePresent(actualResponse);
      delete actualResponse.res;
      assert.deepStrictEqual(actualResponse, {
        token: successfulRefreshResponse.access_token,
      });

      scope.done();
    });
  });

  describe('getRequestHeaders()', () => {
    it('should inject the authorization headers', async () => {
      const expectedHeaders = {
        Authorization: `Bearer ${successfulRefreshResponseNoRefreshToken.access_token}`,
        'x-goog-user-project': 'quotaProjectId',
      };
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 200,
          response: successfulRefreshResponseNoRefreshToken,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const optionsWithQuotaProjectId = Object.assign(
        {quota_project_id: 'quotaProjectId'},
        externalAccountAuthorizedUserCredentialOptions
      );
      const client = new ExternalAccountAuthorizedUserClient(
        optionsWithQuotaProjectId
      );
      const actualHeaders = await client.getRequestHeaders();

      assert.deepStrictEqual(actualHeaders, expectedHeaders);
      scope.done();
    });

    it('should reject when error occurs during token retrieval', async () => {
      const errorResponse: OAuthErrorResponse = {
        error: 'invalid_request',
        error_description: 'Invalid subject token',
        error_uri: 'https://tools.ietf.org/html/rfc6749#section-5.2',
      };
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
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
        Authorization: `Bearer ${successfulRefreshResponse.access_token}`,
        'x-goog-user-project': quotaProjectId,
      };
      const optionsWithQuotaProjectId = Object.assign(
        {quota_project_id: quotaProjectId},
        externalAccountAuthorizedUserCredentialOptions
      );
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        optionsWithQuotaProjectId
      );
      const actualResponse = await client.request<Object>({
        url: 'https://example.com/api',
        method: 'POST',
        headers: exampleHeaders,
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
      const scope = mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
        {
          statusCode: 400,
          response: errorResponse,
          request: {
            grant_type: 'refresh_token',
            refresh_token: 'refreshToken',
          },
        },
      ]);

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      await assert.rejects(
        client.request<Object>({
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
        Authorization: `Bearer ${successfulRefreshResponse.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      client.request<Object>(
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
        Authorization: `Bearer ${successfulRefreshResponse.access_token}`,
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
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(400, errorMessage),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      client.request<Object>(
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
      const authHeaders = {
        Authorization: `Bearer ${successfulRefreshResponseNoRefreshToken.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const exampleHeaders = {
        custom: 'some-header-value',
        other: 'other-header-value',
      };
      const scopes = [
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
            times: 2,
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(401)
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions,
        {
          forceRefreshOnFailure: true,
        }
      );
      const actualResponse = await client.request<Object>({
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
        Authorization: `Bearer ${successfulRefreshResponse.access_token}`,
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
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponse,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(401),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions,
        {
          forceRefreshOnFailure: false,
        }
      );
      await assert.rejects(
        client.request<Object>({
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
      const authHeaders = {
        Authorization: `Bearer ${successfulRefreshResponseNoRefreshToken.access_token}`,
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
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
            times: 2,
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(403)
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, exampleHeaders, authHeaders),
          })
          .reply(403),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions,
        {
          forceRefreshOnFailure: true,
        }
      );
      await assert.rejects(
        client.request<Object>({
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

    it('should process headerless HTTP request', async () => {
      const authHeaders = {
        Authorization: `Bearer ${successfulRefreshResponse.access_token}`,
      };
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const exampleResponse = {
        foo: 'a',
        bar: 1,
      };
      const scopes = [
        mockStsTokenRefresh(BASE_URL, REFRESH_PATH, [
          {
            statusCode: 200,
            response: successfulRefreshResponseNoRefreshToken,
            request: {
              grant_type: 'refresh_token',
              refresh_token: 'refreshToken',
            },
          },
        ]),
        nock('https://example.com')
          .post('/api', exampleRequest, {
            reqheaders: Object.assign({}, authHeaders),
          })
          .reply(200, Object.assign({}, exampleResponse)),
      ];

      const client = new ExternalAccountAuthorizedUserClient(
        externalAccountAuthorizedUserCredentialOptions
      );
      // Send request with no headers.
      const actualResponse = await client.request<Object>({
        url: 'https://example.com/api',
        method: 'POST',
        data: exampleRequest,
        responseType: 'json',
      });

      assert.deepStrictEqual(actualResponse.data, exampleResponse);
      scopes.forEach(scope => scope.done());
    });
  });
});
