// Copyright 2021 Google LLC
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
import {describe, it, beforeEach, afterEach} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';

import {GaxiosOptions, GaxiosPromise} from 'gaxios';
import {StsSuccessfulResponse} from '../src/auth/stscredentials';
import {
  DownscopedClient,
  CredentialAccessBoundary,
  MAX_ACCESS_BOUNDARY_RULES_COUNT,
} from '../src/auth/downscopedclient';
import {AuthClient} from '../src/auth/authclient';
import {mockStsTokenExchange} from './externalclienthelper';
import {
  OAuthErrorResponse,
  getErrorFromOAuthErrorResponse,
} from '../src/auth/oauth2common';
import {GetAccessTokenResponse, Headers} from '../src/auth/oauth2client';

nock.disableNetConnect();

/** A dummy class used as source credential for testing. */
class TestAuthClient extends AuthClient {
  public throwError = false;
  private counter = 0;

  async getAccessToken(): Promise<GetAccessTokenResponse> {
    if (!this.throwError) {
      // Increment subject_token counter each time this is called.
      return {
        token: `subject_token_${this.counter++}`,
      };
    }
    throw new Error('Cannot get subject token.');
  }

  async getRequestHeaders(url?: string): Promise<Headers> {
    throw new Error('Not implemented.');
  }

  request<T>(opts: GaxiosOptions): GaxiosPromise<T> {
    throw new Error('Not implemented.');
  }
}

interface SampleResponse {
  foo: string;
  bar: number;
}

describe('DownscopedClient', () => {
  let clock: sinon.SinonFakeTimers;
  let client: TestAuthClient;

  const ONE_HOUR_IN_SECS = 3600;
  const testAvailableResource =
    '//storage.googleapis.com/projects/_/buckets/bucket-123';
  const testAvailablePermission1 = 'inRole:roles/storage.objectViewer';
  const testAvailablePermission2 = 'inRole:roles/storage.objectAdmin';
  const testAvailabilityConditionExpression =
    "resource.name.startsWith('projects/_/buckets/bucket-123/objects/prefix')";
  const testAvailabilityConditionTitle = 'Test availability condition title.';
  const testAvailabilityConditionDescription =
    'Test availability condition description.';
  const testClientAccessBoundary = {
    accessBoundary: {
      accessBoundaryRules: [
        {
          availableResource: testAvailableResource,
          availablePermissions: [testAvailablePermission1],
          availabilityCondition: {
            expression: testAvailabilityConditionExpression,
          },
        },
      ],
    },
  };
  const stsSuccessfulResponse: StsSuccessfulResponse = {
    access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN_0',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: ONE_HOUR_IN_SECS,
  };
  /**
   * Offset to take into account network delays and server clock skews.
   */
  const EXPIRATION_TIME_OFFSET = 5 * 60 * 1000;

  beforeEach(async () => {
    client = new TestAuthClient();
  });

  afterEach(() => {
    nock.cleanAll();
    if (clock) {
      clock.restore();
    }
  });

  describe('Constructor', () => {
    it('should throw on empty access boundary rule', () => {
      const expectedError = new Error(
        'At least one access boundary rule needs to be defined.'
      );
      const cabWithEmptyAccessBoundaryRules = {
        accessBoundary: {
          accessBoundaryRules: [],
        },
      };
      assert.throws(() => {
        return new DownscopedClient(client, cabWithEmptyAccessBoundaryRules);
      }, expectedError);
    });

    it('should throw when number of access boundary rules is exceeded', () => {
      const expectedError = new Error(
        'The provided access boundary has more than ' +
          `${MAX_ACCESS_BOUNDARY_RULES_COUNT} access boundary rules.`
      );
      const cabWithExceedingAccessBoundaryRules: CredentialAccessBoundary = {
        accessBoundary: {
          accessBoundaryRules: [],
        },
      };
      const testAccessBoundaryRule = {
        availableResource: testAvailableResource,
        availablePermissions: [testAvailablePermission1],
        availabilityCondition: {
          expression: testAvailabilityConditionExpression,
        },
      };
      for (let num = 0; num <= MAX_ACCESS_BOUNDARY_RULES_COUNT; num++) {
        cabWithExceedingAccessBoundaryRules.accessBoundary.accessBoundaryRules.push(
          testAccessBoundaryRule
        );
      }
      assert.throws(() => {
        return new DownscopedClient(
          client,
          cabWithExceedingAccessBoundaryRules
        );
      }, expectedError);
    });

    it('should throw on no permissions are defined in access boundary rules', () => {
      const expectedError = new Error(
        'At least one permission should be defined in access boundary rules.'
      );
      const cabWithNoPermissionIncluded = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.throws(() => {
        return new DownscopedClient(client, cabWithNoPermissionIncluded);
      }, expectedError);
    });

    it('should not throw on one access boundary rule with all fields included', () => {
      const cabWithOneAccessBoundaryRule = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithOneAccessBoundaryRule);
      });
    });

    it('should not throw with multiple permissions defined', () => {
      const cabWithTwoAvailblePermissions = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [
                testAvailablePermission1,
                testAvailablePermission2,
              ],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
                title: testAvailabilityConditionTitle,
                description: testAvailabilityConditionDescription,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithTwoAvailblePermissions);
      });
    });

    it('should not throw with empty available condition', () => {
      const cabWithNoAvailabilityCondition = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithNoAvailabilityCondition);
      });
    });

    it('should not throw with only expression setup in available condition', () => {
      const cabWithOnlyAvailabilityConditionExpression = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [
                testAvailablePermission1,
                testAvailablePermission2,
              ],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(
          client,
          cabWithOnlyAvailabilityConditionExpression
        );
      });
    });

    it('should set custom RefreshOptions', () => {
      const refreshOptions = {
        eagerRefreshThresholdMillis: 5000,
        forceRefreshOnFailure: true,
      };
      const cabWithOneAccessBoundaryRules = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      const downscopedClient = new DownscopedClient(
        client,
        cabWithOneAccessBoundaryRules,
        refreshOptions
      );
      assert.strictEqual(
        downscopedClient.forceRefreshOnFailure,
        refreshOptions.forceRefreshOnFailure
      );
      assert.strictEqual(
        downscopedClient.eagerRefreshThresholdMillis,
        refreshOptions.eagerRefreshThresholdMillis
      );
    });
  });

  describe('setCredential()', () => {
    it('should throw error if no expire time is set in credential', async () => {
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
      };
      const expectedError = new Error(
        'The access token expiry_date field is missing in the provided ' +
          'credentials.'
      );
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      assert.throws(() => {
        downscopedClient.setCredentials(credentials);
      }, expectedError);
    });

    it('should not throw error if expire time is set in credential', async () => {
      const now = new Date().getTime();
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      assert.doesNotThrow(() => {
        downscopedClient.setCredentials(credentials);
      });
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);
      assert.deepStrictEqual(
        tokenResponse.expirationTime,
        credentials.expiry_date
      );
    });
  });

  describe('getAccessToken()', () => {
    it('should return current unexpired cached DownscopedClient access token', async () => {
      const now = new Date().getTime();
      clock = sinon.useFakeTimers(now);
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      downscopedClient.setCredentials(credentials);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);
      assert.deepStrictEqual(
        tokenResponse.expirationTime,
        credentials.expiry_date
      );
      assert.deepStrictEqual(
        tokenResponse.token,
        downscopedClient.credentials.access_token
      );
      assert.deepStrictEqual(
        tokenResponse.expirationTime,
        downscopedClient.credentials.expiry_date
      );

      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const cachedTokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        cachedTokenResponse.token,
        credentials.access_token
      );
      assert.deepStrictEqual(
        cachedTokenResponse.expirationTime,
        credentials.expiry_date
      );
    });

    it('should refresh a new DownscopedClient access when cached one gets expired', async () => {
      const now = new Date().getTime();
      clock = sinon.useFakeTimers(now);
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options: JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);

      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      downscopedClient.setCredentials(credentials);

      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);

      clock.tick(1);
      const refreshedTokenResponse = await downscopedClient.getAccessToken();
      const expectedExpirationTime =
        credentials.expiry_date +
        stsSuccessfulResponse.expires_in * 1000 -
        EXPIRATION_TIME_OFFSET;
      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        stsSuccessfulResponse.access_token
      );
      assert.deepStrictEqual(
        refreshedTokenResponse.expirationTime,
        expectedExpirationTime
      );
      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        downscopedClient.credentials.access_token
      );
      assert.deepStrictEqual(
        refreshedTokenResponse.expirationTime,
        downscopedClient.credentials.expiry_date
      );
      scope.done();
    });

    it('should return new access token when no cached token is available', async () => {
      const scope = mockStsTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options: JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      assert.deepStrictEqual(downscopedClient.credentials, {});
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        tokenResponse.token,
        stsSuccessfulResponse.access_token
      );
      assert.deepStrictEqual(
        tokenResponse.token,
        downscopedClient.credentials.access_token
      );
      assert.deepStrictEqual(
        tokenResponse.expirationTime,
        downscopedClient.credentials.expiry_date
      );
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
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_0',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options: JSON.stringify(testClientAccessBoundary),
          },
        },
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token_1',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options: JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);

      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      assert.deepStrictEqual(downscopedClient.credentials, {});
      await assert.rejects(
        downscopedClient.getAccessToken(),
        getErrorFromOAuthErrorResponse(errorResponse)
      );
      assert.deepStrictEqual(downscopedClient.credentials, {});
      // Next try should succeed.
      const actualResponse = await downscopedClient.getAccessToken();
      delete actualResponse.res;
      assert.deepStrictEqual(
        actualResponse.token,
        stsSuccessfulResponse.access_token
      );
      assert.deepStrictEqual(
        actualResponse.token,
        downscopedClient.credentials.access_token
      );
      assert.deepStrictEqual(
        actualResponse.expirationTime,
        downscopedClient.credentials.expiry_date
      );
      scope.done();
    });

    it('should throw when the source AuthClient rejects on token request', async () => {
      const expectedError = new Error('Cannot get subject token.');
      client.throwError = true;
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      await assert.rejects(downscopedClient.getAccessToken(), expectedError);
    });
  });

  describe('getRequestHeader()', () => {
    it('should return unimplemented error when calling getRequestHeader()', async () => {
      const expectedError = new Error('Not implemented.');
      const cabClient = new DownscopedClient(client, testClientAccessBoundary);
      await assert.rejects(cabClient.getRequestHeaders(), expectedError);
    });
  });

  describe('request()', () => {
    it('should return unimplemented error when request with opts', () => {
      const cabClient = new DownscopedClient(client, testClientAccessBoundary);
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const expectedError = new Error('Not implemented.');

      assert.throws(() => {
        return cabClient.request<SampleResponse>({
          url: 'https://example.com/api',
          method: 'POST',
          data: exampleRequest,
          responseType: 'json',
        });
      }, expectedError);
    });
  });
});
