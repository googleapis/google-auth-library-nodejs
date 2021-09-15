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
import {describe, it, afterEach, beforeEach} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';
import {AwsClient} from '../src/auth/awsclient';
import {StsSuccessfulResponse} from '../src/auth/stscredentials';
import {BaseExternalAccountClient} from '../src/auth/baseexternalclient';
import {
  assertGaxiosResponsePresent,
  getAudience,
  getTokenUrl,
  getServiceAccountImpersonationUrl,
  mockGenerateAccessToken,
  mockStsTokenExchange,
} from './externalclienthelper';

nock.disableNetConnect();

const ONE_HOUR_IN_SECS = 3600;

describe('AwsClient', () => {
  let clock: sinon.SinonFakeTimers;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const awsSecurityCredentials = require('../../test/fixtures/aws-security-credentials-fake.json');
  const referenceDate = new Date('2020-08-11T06:55:22.345Z');
  const amzDate = '20200811T065522Z';
  const dateStamp = '20200811';
  const awsRegion = 'us-east-2';
  const accessKeyId = awsSecurityCredentials.AccessKeyId;
  const secretAccessKey = awsSecurityCredentials.SecretAccessKey;
  const token = awsSecurityCredentials.Token;
  const awsRole = 'gcp-aws-role';
  const audience = getAudience();
  const metadataBaseUrl = 'http://169.254.169.254';
  const awsCredentialSource = {
    environment_id: 'aws1',
    region_url: `${metadataBaseUrl}/latest/meta-data/placement/availability-zone`,
    url: `${metadataBaseUrl}/latest/meta-data/iam/security-credentials`,
    regional_cred_verification_url:
      'https://sts.{region}.amazonaws.com?' +
      'Action=GetCallerIdentity&Version=2011-06-15',
  };
  const awsOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
    token_url: getTokenUrl(),
    credential_source: awsCredentialSource,
  };
  const awsOptionsWithSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    awsOptions
  );
  const stsSuccessfulResponse: StsSuccessfulResponse = {
    access_token: 'ACCESS_TOKEN',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: ONE_HOUR_IN_SECS,
    scope: 'scope1 scope2',
  };
  // Signature retrieved from "signed POST request" test in test.awsclient.ts.
  const expectedSignedRequest = {
    url:
      'https://sts.us-east-2.amazonaws.com' +
      '?Action=GetCallerIdentity&Version=2011-06-15',
    method: 'POST',
    headers: {
      Authorization:
        `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
        `${dateStamp}/${awsRegion}/sts/aws4_request, SignedHeaders=host;` +
        'x-amz-date;x-amz-security-token, Signature=' +
        '73452984e4a880ffdc5c392355733ec3f5ba310d5e0609a89244440cadfe7a7a',
      host: 'sts.us-east-2.amazonaws.com',
      'x-amz-date': amzDate,
      'x-amz-security-token': token,
    },
  };
  const expectedSubjectToken = encodeURIComponent(
    JSON.stringify({
      url: expectedSignedRequest.url,
      method: expectedSignedRequest.method,
      headers: [
        {
          key: 'x-goog-cloud-target-resource',
          value: awsOptions.audience,
        },
        {
          key: 'x-amz-date',
          value: expectedSignedRequest.headers['x-amz-date'],
        },
        {
          key: 'Authorization',
          value: expectedSignedRequest.headers.Authorization,
        },
        {
          key: 'host',
          value: expectedSignedRequest.headers.host,
        },
        {
          key: 'x-amz-security-token',
          value: expectedSignedRequest.headers['x-amz-security-token'],
        },
      ],
    })
  );
  // Signature retrieved from "signed request when AWS credentials have no
  // token" test in test.awsclient.ts.
  const expectedSignedRequestNoToken = {
    url:
      'https://sts.us-east-2.amazonaws.com' +
      '?Action=GetCallerIdentity&Version=2011-06-15',
    method: 'POST',
    headers: {
      Authorization:
        `AWS4-HMAC-SHA256 Credential=${accessKeyId}/` +
        `${dateStamp}/${awsRegion}/sts/aws4_request, SignedHeaders=host;` +
        'x-amz-date, Signature=' +
        'd095ba304919cd0d5570ba8a3787884ee78b860f268ed040ba23831d55536d56',
      host: 'sts.us-east-2.amazonaws.com',
      'x-amz-date': amzDate,
    },
  };
  const expectedSubjectTokenNoToken = encodeURIComponent(
    JSON.stringify({
      url: expectedSignedRequestNoToken.url,
      method: expectedSignedRequestNoToken.method,
      headers: [
        {
          key: 'x-goog-cloud-target-resource',
          value: awsOptions.audience,
        },
        {
          key: 'x-amz-date',
          value: expectedSignedRequestNoToken.headers['x-amz-date'],
        },
        {
          key: 'Authorization',
          value: expectedSignedRequestNoToken.headers.Authorization,
        },
        {
          key: 'host',
          value: expectedSignedRequestNoToken.headers.host,
        },
      ],
    })
  );

  beforeEach(() => {
    clock = sinon.useFakeTimers(referenceDate);
  });

  afterEach(() => {
    if (clock) {
      clock.restore();
    }
  });

  it('should be a subclass of ExternalAccountClient', () => {
    assert(AwsClient.prototype instanceof BaseExternalAccountClient);
  });

  describe('Constructor', () => {
    const requiredCredentialSourceFields = [
      'environment_id',
      'regional_cred_verification_url',
    ];
    requiredCredentialSourceFields.forEach(required => {
      it(`should throw when credential_source is missing ${required}`, () => {
        const expectedError = new Error(
          'No valid AWS "credential_source" provided'
        );
        const invalidCredentialSource = Object.assign({}, awsCredentialSource);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        delete (invalidCredentialSource as any)[required];
        const invalidOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
          token_url: getTokenUrl(),
          credential_source: invalidCredentialSource,
        };

        assert.throws(() => {
          return new AwsClient(invalidOptions);
        }, expectedError);
      });
    });

    it('should throw when an unsupported environment ID is provided', () => {
      const expectedError = new Error(
        'No valid AWS "credential_source" provided'
      );
      const invalidCredentialSource = Object.assign({}, awsCredentialSource);
      invalidCredentialSource.environment_id = 'azure1';
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
        token_url: getTokenUrl(),
        credential_source: invalidCredentialSource,
      };

      assert.throws(() => {
        return new AwsClient(invalidOptions);
      }, expectedError);
    });

    it('should throw when an unsupported environment version is provided', () => {
      const expectedError = new Error(
        'aws version "3" is not supported in the current build.'
      );
      const invalidCredentialSource = Object.assign({}, awsCredentialSource);
      invalidCredentialSource.environment_id = 'aws3';
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
        token_url: getTokenUrl(),
        credential_source: invalidCredentialSource,
      };

      assert.throws(() => {
        return new AwsClient(invalidOptions);
      }, expectedError);
    });

    it('should not throw when valid AWS options are provided', () => {
      assert.doesNotThrow(() => {
        return new AwsClient(awsOptions);
      });
    });
  });

  describe('for security_credentials retrieved tokens', () => {
    describe('retrieveSubjectToken()', () => {
      it('should resolve on success', async () => {
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(200, awsRole)
          .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
          .reply(200, awsSecurityCredentials);

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectToken);
        scope.done();
      });

      it('should resolve on success with permanent creds', async () => {
        const permanentAwsSecurityCredentials = Object.assign(
          {},
          awsSecurityCredentials
        );
        delete permanentAwsSecurityCredentials.Token;
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(200, awsRole)
          .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
          .reply(200, permanentAwsSecurityCredentials);

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
        scope.done();
      });

      it('should re-calculate role name on successive calls', async () => {
        const otherRole = 'some-other-role';
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(200, awsRole)
          .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
          .reply(200, awsSecurityCredentials)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(200, otherRole)
          .get(`/latest/meta-data/iam/security-credentials/${otherRole}`)
          .reply(200, awsSecurityCredentials);

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();
        const subjectToken2 = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectToken);
        assert.deepEqual(subjectToken2, expectedSubjectToken);
        scope.done();
      });

      it('should reject when AWS region is not determined', async () => {
        // Simulate error during region retrieval.
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(500);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.retrieveSubjectToken(), {
          code: '500',
        });
        scope.done();
      });

      it('should reject when AWS role name is not determined', async () => {
        // Simulate error during region retrieval.
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(403);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.retrieveSubjectToken(), {
          code: '403',
        });
        scope.done();
      });

      it('should reject when AWS security creds are not found', async () => {
        // Simulate error during security credentials retrieval.
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(200, awsRole)
          .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
          .reply(408);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.retrieveSubjectToken(), {
          code: '408',
        });
        scope.done();
      });

      it('should reject when "credential_source.url" is missing', async () => {
        const expectedError = new Error(
          'Unable to determine AWS role name due to missing ' +
            '"options.credential_source.url"'
        );
        const missingUrlCredentialSource = Object.assign(
          {},
          awsCredentialSource
        );
        delete missingUrlCredentialSource.url;
        const invalidOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
          token_url: getTokenUrl(),
          credential_source: missingUrlCredentialSource,
        };
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`);

        const client = new AwsClient(invalidOptions);

        await assert.rejects(client.retrieveSubjectToken(), expectedError);
        scope.done();
      });

      it('should reject when "credential_source.region_url" is missing', async () => {
        const expectedError = new Error(
          'Unable to determine AWS region due to missing ' +
            '"options.credential_source.region_url"'
        );
        const missingRegionUrlCredentialSource = Object.assign(
          {},
          awsCredentialSource
        );
        delete missingRegionUrlCredentialSource.region_url;
        const invalidOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
          token_url: getTokenUrl(),
          credential_source: missingRegionUrlCredentialSource,
        };

        const client = new AwsClient(invalidOptions);

        await assert.rejects(client.retrieveSubjectToken(), expectedError);
      });
    });

    describe('getAccessToken()', () => {
      it('should resolve on retrieveSubjectToken success', async () => {
        const scopes: nock.Scope[] = [];
        scopes.push(
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
                subject_token: expectedSubjectToken,
                subject_token_type:
                  'urn:ietf:params:aws:token-type:aws4_request',
              },
            },
          ])
        );
        scopes.push(
          nock(metadataBaseUrl)
            .get('/latest/meta-data/placement/availability-zone')
            .reply(200, `${awsRegion}b`)
            .get('/latest/meta-data/iam/security-credentials')
            .reply(200, awsRole)
            .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
            .reply(200, awsSecurityCredentials)
        );

        const client = new AwsClient(awsOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should handle service account access token', async () => {
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(
            referenceDate.getTime() + ONE_HOUR_IN_SECS * 1000
          ).toISOString(),
        };
        const scopes: nock.Scope[] = [];
        scopes.push(
          nock(metadataBaseUrl)
            .get('/latest/meta-data/placement/availability-zone')
            .reply(200, `${awsRegion}b`)
            .get('/latest/meta-data/iam/security-credentials')
            .reply(200, awsRole)
            .get(`/latest/meta-data/iam/security-credentials/${awsRole}`)
            .reply(200, awsSecurityCredentials),
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
                subject_token: expectedSubjectToken,
                subject_token_type:
                  'urn:ietf:params:aws:token-type:aws4_request',
              },
            },
          ]),
          mockGenerateAccessToken([
            {
              statusCode: 200,
              response: saSuccessResponse,
              token: stsSuccessfulResponse.access_token,
              scopes: ['https://www.googleapis.com/auth/cloud-platform'],
            },
          ])
        );

        const client = new AwsClient(awsOptionsWithSA);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should reject on retrieveSubjectToken error', async () => {
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`)
          .get('/latest/meta-data/iam/security-credentials')
          .reply(500);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.getAccessToken(), {
          code: '500',
        });
        scope.done();
      });
    });
  });

  describe('for environment variables retrieved tokens', () => {
    let envAwsAccessKeyId: string | undefined;
    let envAwsSecretAccessKey: string | undefined;
    let envAwsSessionToken: string | undefined;
    let envAwsRegion: string | undefined;
    let envAwsDefaultRegion: string | undefined;

    beforeEach(() => {
      // Store external state.
      envAwsAccessKeyId = process.env.AWS_ACCESS_KEY_ID;
      envAwsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
      envAwsSessionToken = process.env.AWS_SESSION_TOKEN;
      envAwsRegion = process.env.AWS_REGION;
      envAwsDefaultRegion = process.env.AWS_DEFAULT_REGION;
      // Reset environment variables.
      delete process.env.AWS_ACCESS_KEY_ID;
      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.AWS_SESSION_TOKEN;
      delete process.env.AWS_REGION;
      delete process.env.AWS_DEFAULT_REGION;
    });

    afterEach(() => {
      // Restore environment variables.
      if (envAwsAccessKeyId) {
        process.env.AWS_ACCESS_KEY_ID = envAwsAccessKeyId;
      } else {
        delete process.env.AWS_ACCESS_KEY_ID;
      }
      if (envAwsSecretAccessKey) {
        process.env.AWS_SECRET_ACCESS_KEY = envAwsSecretAccessKey;
      } else {
        delete process.env.AWS_SECRET_ACCESS_KEY;
      }
      if (envAwsSessionToken) {
        process.env.AWS_SESSION_TOKEN = envAwsSessionToken;
      } else {
        delete process.env.AWS_SESSION_TOKEN;
      }
      if (envAwsRegion) {
        process.env.AWS_REGION = envAwsRegion;
      } else {
        delete process.env.AWS_REGION;
      }
      if (envAwsDefaultRegion) {
        process.env.AWS_DEFAULT_REGION = envAwsDefaultRegion;
      } else {
        delete process.env.AWS_DEFAULT_REGION;
      }
    });

    describe('retrieveSubjectToken()', () => {
      it('should resolve on success for permanent creds', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;

        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`);

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
        scope.done();
      });

      it('should resolve on success for temporary creds', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
        process.env.AWS_SESSION_TOKEN = token;

        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(200, `${awsRegion}b`);

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectToken);
        scope.done();
      });

      it('should reject when AWS region is not determined', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;

        // Simulate error during region retrieval.
        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(500);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.retrieveSubjectToken(), {
          code: '500',
        });
        scope.done();
      });

      it('should resolve when AWS_REGION is set as environment variable', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
        process.env.AWS_REGION = awsRegion;

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
      });

      it('should resolve when AWS_DEFAULT_REGION is set as environment variable', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
        process.env.AWS_DEFAULT_REGION = awsRegion;

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
      });

      it('should prioritize AWS_REGION over AWS_DEFAULT_REGION environment variable', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
        process.env.AWS_REGION = awsRegion;
        process.env.AWS_DEFAULT_REGION = 'fail-if-used';

        const client = new AwsClient(awsOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
      });

      it('should resolve without optional credentials_source fields', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
        process.env.AWS_REGION = awsRegion;
        const requiredOnlyCredentialSource = Object.assign(
          {},
          awsCredentialSource
        );
        // Remove all optional fields.
        delete requiredOnlyCredentialSource.region_url;
        delete requiredOnlyCredentialSource.url;
        const requiredOnlyOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
          token_url: getTokenUrl(),
          credential_source: requiredOnlyCredentialSource,
        };

        const client = new AwsClient(requiredOnlyOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, expectedSubjectTokenNoToken);
      });
    });

    describe('getAccessToken()', () => {
      it('should resolve on retrieveSubjectToken success', async () => {
        const scopes: nock.Scope[] = [];
        scopes.push(
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
                subject_token: expectedSubjectTokenNoToken,
                subject_token_type:
                  'urn:ietf:params:aws:token-type:aws4_request',
              },
            },
          ])
        );
        scopes.push(
          nock(metadataBaseUrl)
            .get('/latest/meta-data/placement/availability-zone')
            .reply(200, `${awsRegion}b`)
        );
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;

        const client = new AwsClient(awsOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should reject on retrieveSubjectToken error', async () => {
        process.env.AWS_ACCESS_KEY_ID = accessKeyId;
        process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;

        const scope = nock(metadataBaseUrl)
          .get('/latest/meta-data/placement/availability-zone')
          .reply(500);

        const client = new AwsClient(awsOptions);

        await assert.rejects(client.getAccessToken(), {
          code: '500',
        });
        scope.done();
      });
    });
  });
});
