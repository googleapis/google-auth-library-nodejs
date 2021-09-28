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
import {describe, it} from 'mocha';
import * as fs from 'fs';
import * as nock from 'nock';
import {createCrypto} from '../src/crypto/crypto';
import {
  IdentityPoolClient,
  IdentityPoolClientOptions,
} from '../src/auth/identitypoolclient';
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

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#Escaping
function escapeRegExp(str: string): string {
  // $& means the whole matched string.
  return str.replace(/[.*+\-?^${}()|[\]\\]/g, '\\$&');
}

describe('IdentityPoolClient', () => {
  const fileSubjectToken = fs.readFileSync(
    './test/fixtures/external-subject-token.txt',
    'utf-8'
  );
  const audience = getAudience();
  const crypto = createCrypto();
  const fileSourcedOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: {
      file: './test/fixtures/external-subject-token.txt',
    },
  };
  const fileSourcedOptionsWithSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    fileSourcedOptions
  );
  const fileSourcedOptionsWithWorkforceUserProject = Object.assign(
    {},
    fileSourcedOptions,
    {
      workforce_pool_user_project: 'workforce_pool_user_project',
      audience:
        '//iam.googleapis.com/locations/global/workforcePools/pool/providers/oidc',
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
    }
  );
  const fileSourcedOptionsWithClientAuthAndWorkforceUserProject = Object.assign(
    {
      client_id: 'CLIENT_ID',
      client_secret: 'SECRET',
    },
    fileSourcedOptionsWithWorkforceUserProject
  );
  const fileSourcedOptionsWithWorkforceUserProjectAndSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    fileSourcedOptionsWithWorkforceUserProject
  );
  const basicAuthCreds =
    `${fileSourcedOptionsWithClientAuthAndWorkforceUserProject.client_id}:` +
    `${fileSourcedOptionsWithClientAuthAndWorkforceUserProject.client_secret}`;
  const jsonFileSourcedOptions: IdentityPoolClientOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: {
      file: './test/fixtures/external-subject-token.json',
      format: {
        type: 'json',
        subject_token_field_name: 'access_token',
      },
    },
  };
  const jsonFileSourcedOptionsWithSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    jsonFileSourcedOptions
  );
  const fileSourcedOptionsNotFound = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: {
      file: './test/fixtures/not-found',
    },
  };
  const metadataBaseUrl = 'http://169.254.169.254';
  const metadataPath =
    '/metadata/identity/oauth2/token?' + 'api-version=2018-02-01&resource=abc';
  const metadataHeaders = {
    Metadata: 'True',
    other: 'some-value',
  };
  const urlSourcedOptions: IdentityPoolClientOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: {
      url: `${metadataBaseUrl}${metadataPath}`,
      headers: metadataHeaders,
    },
  };
  const urlSourcedOptionsWithSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    urlSourcedOptions
  );
  const jsonRespUrlSourcedOptions: IdentityPoolClientOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: {
      url: `${metadataBaseUrl}${metadataPath}`,
      headers: metadataHeaders,
      format: {
        type: 'json',
        subject_token_field_name: 'access_token',
      },
    },
  };
  const jsonRespUrlSourcedOptionsWithSA = Object.assign(
    {
      service_account_impersonation_url: getServiceAccountImpersonationUrl(),
    },
    jsonRespUrlSourcedOptions
  );
  const stsSuccessfulResponse: StsSuccessfulResponse = {
    access_token: 'ACCESS_TOKEN',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: ONE_HOUR_IN_SECS,
    scope: 'scope1 scope2',
  };

  it('should be a subclass of BaseExternalAccountClient', () => {
    assert(IdentityPoolClient.prototype instanceof BaseExternalAccountClient);
  });

  describe('Constructor', () => {
    const invalidWorkforceIdentityPoolClientAudiences = [
      '//iam.googleapis.com/locations/global/workloadIdentityPools/pool/providers/oidc',
      '//iam.googleapis.com/locations/global/workforcepools/pool/providers/oidc',
      '//iam.googleapis.com/locations/global/workforcePools//providers/oidc',
      '//iam.googleapis.com/locations/global/workforcePools/providers/oidc',
      '//iam.googleapis.com/locations/global/workloadIdentityPools/workforcePools/pool/providers/oidc',
      '//iam.googleapis.com//locations/global/workforcePools/pool/providers/oidc',
      '//iam.googleapis.com/project/123/locations/global/workforcePools/pool/providers/oidc',
      '//iam.googleapis.com/locations/global/workforcePools/workloadIdentityPools/pool/providers/oidc',
      '//iam.googleapis.com/locations/global/workforcePools/pool/providers',
      '//iam.googleapis.com/locations/global/workforcePools/pool/providers/',
      '//iam.googleapis.com/locations//workforcePools/pool/providers/oidc',
      '//iam.googleapis.com/locations/workforcePools/pool/providers/oidc',
    ];
    const invalidWorkforceIdentityPoolFileSourceOptions = Object.assign(
      {},
      fileSourcedOptionsWithWorkforceUserProject
    );
    const expectedWorkforcePoolUserProjectError = new Error(
      'workforcePoolUserProject should not be set for non-workforce pool ' +
        'credentials.'
    );

    it('should throw when invalid options are provided', () => {
      const expectedError = new Error(
        'No valid Identity Pool "credential_source" provided'
      );
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: {
          other: 'invalid',
        },
      };

      assert.throws(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return new IdentityPoolClient(invalidOptions as any);
      }, expectedError);
    });

    it('should throw on invalid credential_source.format.type', () => {
      const expectedError = new Error('Invalid credential_source format "xml"');
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: {
          file: './test/fixtures/external-subject-token.txt',
          format: {
            type: 'xml',
          },
        },
      };

      assert.throws(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return new IdentityPoolClient(invalidOptions as any);
      }, expectedError);
    });

    it('should throw on required credential_source.format.subject_token_field_name', () => {
      const expectedError = new Error(
        'Missing subject_token_field_name for JSON credential_source format'
      );
      const invalidOptions: IdentityPoolClientOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: {
          file: './test/fixtures/external-subject-token.txt',
          format: {
            // json formats require the key where the subject_token is located.
            type: 'json',
          },
        },
      };

      assert.throws(() => {
        return new IdentityPoolClient(invalidOptions);
      }, expectedError);
    });

    invalidWorkforceIdentityPoolClientAudiences.forEach(
      invalidWorkforceIdentityPoolClientAudience => {
        it(`should throw given audience ${invalidWorkforceIdentityPoolClientAudience} with user project defined in IdentityPoolClientOptions`, () => {
          invalidWorkforceIdentityPoolFileSourceOptions.audience =
            invalidWorkforceIdentityPoolClientAudience;

          assert.throws(() => {
            return new IdentityPoolClient(
              invalidWorkforceIdentityPoolFileSourceOptions
            );
          }, expectedWorkforcePoolUserProjectError);
        });
      }
    );

    it('should not throw when valid file-sourced options are provided', () => {
      assert.doesNotThrow(() => {
        return new IdentityPoolClient(fileSourcedOptions);
      });
    });

    it('should not throw when valid url-sourced options are provided', () => {
      assert.doesNotThrow(() => {
        return new IdentityPoolClient(urlSourcedOptions);
      });
    });

    it('should not throw on headerless url-sourced options', () => {
      const urlSourcedOptionsNoHeaders = Object.assign({}, urlSourcedOptions);
      urlSourcedOptionsNoHeaders.credential_source = {
        url: urlSourcedOptions.credential_source.url,
      };
      assert.doesNotThrow(() => {
        return new IdentityPoolClient(urlSourcedOptionsNoHeaders);
      });
    });

    it('should not throw on valid workforce audience configs', () => {
      const validWorkforceIdentityPoolClientAudiences = [
        '//iam.googleapis.com/locations/global/workforcePools/workforcePools/providers/provider',
        '//iam.googleapis.com/locations/global/workforcePools/pool/providers/provider',
        '//iam.googleapis.com/locations/global/workforcePools/workloadPools/providers/oidc',
      ];
      const validWorkforceIdentityPoolFileSourceOptions = Object.assign(
        {},
        fileSourcedOptionsWithWorkforceUserProject
      );
      for (const validWorkforceIdentityPoolClientAudience of validWorkforceIdentityPoolClientAudiences) {
        validWorkforceIdentityPoolFileSourceOptions.audience =
          validWorkforceIdentityPoolClientAudience;

        assert.doesNotThrow(() => {
          return new IdentityPoolClient(
            validWorkforceIdentityPoolFileSourceOptions
          );
        });
      }
    });
  });

  describe('for file-sourced subject tokens', () => {
    describe('retrieveSubjectToken()', () => {
      it('should resolve when the text file is found', async () => {
        const client = new IdentityPoolClient(fileSourcedOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, fileSubjectToken);
      });

      it('should resolve when the json file is found', async () => {
        const client = new IdentityPoolClient(jsonFileSourcedOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, fileSubjectToken);
      });

      it('should reject when the json subject_token_field_name is not found', async () => {
        const expectedError = new Error(
          'Unable to parse the subject_token from the credential_source file'
        );
        const invalidOptions: IdentityPoolClientOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: getTokenUrl(),
          credential_source: {
            file: './test/fixtures/external-subject-token.json',
            format: {
              type: 'json',
              subject_token_field_name: 'non-existent',
            },
          },
        };
        const client = new IdentityPoolClient(invalidOptions);

        await assert.rejects(client.retrieveSubjectToken(), expectedError);
      });

      it('should fail when the file is not found', async () => {
        const invalidFile = fileSourcedOptionsNotFound.credential_source.file;
        const client = new IdentityPoolClient(fileSourcedOptionsNotFound);

        await assert.rejects(
          client.retrieveSubjectToken(),
          new RegExp(
            `The file at ${escapeRegExp(invalidFile)} does not exist, ` +
              'or it is not a file'
          )
        );
      });

      it('should fail when a folder is specified', async () => {
        const invalidOptions = Object.assign({}, fileSourcedOptions);
        invalidOptions.credential_source = {
          // Specify a folder.
          file: './test/fixtures',
        };
        const invalidFile = fs.realpathSync(
          invalidOptions.credential_source.file
        );
        const client = new IdentityPoolClient(invalidOptions);

        await assert.rejects(
          client.retrieveSubjectToken(),
          new RegExp(
            `The file at ${escapeRegExp(invalidFile)} does not exist, ` +
              'or it is not a file'
          )
        );
      });
    });

    describe('getAccessToken()', () => {
      it('should resolve on retrieveSubjectToken success for text format', async () => {
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
              // Subject token loaded from file should be used.
              subject_token: fileSubjectToken,
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]);

        const client = new IdentityPoolClient(fileSourcedOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scope.done();
      });

      it('should resolve with the expected response on workforce configs with client auth', async () => {
        const scope = mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience:
                '//iam.googleapis.com/locations/global/workforcePools/pool/providers/oidc',
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              // Subject token loaded from file should be used.
              subject_token: fileSubjectToken,
              subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
            },
            additionalHeaders: {
              Authorization: `Basic ${crypto.encodeBase64StringUtf8(
                basicAuthCreds
              )}`,
            },
          },
        ]);

        const client = new IdentityPoolClient(
          fileSourcedOptionsWithClientAuthAndWorkforceUserProject
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

      it('should resolve with the expected response on workforce configs without client auth', async () => {
        const scope = mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience:
                '//iam.googleapis.com/locations/global/workforcePools/pool/providers/oidc',
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              // Subject token loaded from file should be used.
              subject_token: fileSubjectToken,
              subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
              options: JSON.stringify({
                userProject:
                  fileSourcedOptionsWithWorkforceUserProject.workforce_pool_user_project,
              }),
            },
          },
        ]);

        const client = new IdentityPoolClient(
          fileSourcedOptionsWithWorkforceUserProject
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

      it('should not throw if client auth is provided but workforce user project is not', async () => {
        const scope = mockStsTokenExchange([
          {
            statusCode: 200,
            response: stsSuccessfulResponse,
            request: {
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              audience:
                '//iam.googleapis.com/locations/global/workforcePools/pool/providers/oidc',
              scope: 'https://www.googleapis.com/auth/cloud-platform',
              requested_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              subject_token: fileSubjectToken,
              subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
            },
            additionalHeaders: {
              Authorization: `Basic ${crypto.encodeBase64StringUtf8(
                basicAuthCreds
              )}`,
            },
          },
        ]);
        const fileSourcedOptionsWithClientAuth: IdentityPoolClientOptions =
          Object.assign(
            {},
            fileSourcedOptionsWithClientAuthAndWorkforceUserProject
          );
        delete fileSourcedOptionsWithClientAuth.workforce_pool_user_project;

        const client = new IdentityPoolClient(fileSourcedOptionsWithClientAuth);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scope.done();
      });

      it('should still pass workforce user project when impersonation and no client auth are used', async () => {
        const now = new Date().getTime();
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(now + ONE_HOUR_IN_SECS * 1000).toISOString(),
        };
        const scopes: nock.Scope[] = [];
        scopes.push(
          mockStsTokenExchange([
            {
              statusCode: 200,
              response: stsSuccessfulResponse,
              request: {
                grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
                audience:
                  '//iam.googleapis.com/locations/global/workforcePools/pool/providers/oidc',
                scope: 'https://www.googleapis.com/auth/cloud-platform',
                requested_token_type:
                  'urn:ietf:params:oauth:token-type:access_token',
                subject_token: fileSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
                options: JSON.stringify({
                  userProject:
                    fileSourcedOptionsWithWorkforceUserProjectAndSA.workforce_pool_user_project,
                }),
              },
            },
          ])
        );
        scopes.push(
          mockGenerateAccessToken([
            {
              statusCode: 200,
              response: saSuccessResponse,
              token: stsSuccessfulResponse.access_token,
              scopes: ['https://www.googleapis.com/auth/cloud-platform'],
            },
          ])
        );

        const client = new IdentityPoolClient(
          fileSourcedOptionsWithWorkforceUserProjectAndSA
        );
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should handle service account access token for text format', async () => {
        const now = new Date().getTime();
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(now + ONE_HOUR_IN_SECS * 1000).toISOString(),
        };
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
                // Subject token loaded from file should be used.
                subject_token: fileSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
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

        const client = new IdentityPoolClient(fileSourcedOptionsWithSA);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should resolve on retrieveSubjectToken success for json format', async () => {
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
              // Subject token loaded from file should be used.
              subject_token: fileSubjectToken,
              subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
            },
          },
        ]);

        const client = new IdentityPoolClient(jsonFileSourcedOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scope.done();
      });

      it('should handle service account access token for json format', async () => {
        const now = new Date().getTime();
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(now + ONE_HOUR_IN_SECS * 1000).toISOString(),
        };
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
                // Subject token loaded from file should be used.
                subject_token: fileSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
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

        const client = new IdentityPoolClient(jsonFileSourcedOptionsWithSA);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should reject with retrieveSubjectToken error', async () => {
        const invalidFile = fileSourcedOptionsNotFound.credential_source.file;
        const client = new IdentityPoolClient(fileSourcedOptionsNotFound);

        await assert.rejects(
          client.getAccessToken(),
          new RegExp(
            `The file at ${invalidFile} does not exist, or it is not a file`
          )
        );
      });
    });
  });

  describe('for url-sourced subject tokens', () => {
    describe('retrieveSubjectToken()', () => {
      it('should resolve on text response success', async () => {
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const scope = nock(metadataBaseUrl)
          .get(metadataPath, undefined, {
            reqheaders: metadataHeaders,
          })
          .reply(200, externalSubjectToken);

        const client = new IdentityPoolClient(urlSourcedOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, externalSubjectToken);
        scope.done();
      });

      it('should resolve on json response success', async () => {
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const jsonResponse = {
          access_token: externalSubjectToken,
        };
        const scope = nock(metadataBaseUrl)
          .get(metadataPath, undefined, {
            reqheaders: metadataHeaders,
          })
          .reply(200, jsonResponse);

        const client = new IdentityPoolClient(jsonRespUrlSourcedOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, externalSubjectToken);
        scope.done();
      });

      it('should reject when the json subject_token_field_name is not found', async () => {
        const expectedError = new Error(
          'Unable to parse the subject_token from the credential_source URL'
        );
        const invalidOptions: IdentityPoolClientOptions = {
          type: 'external_account',
          audience,
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: getTokenUrl(),
          credential_source: {
            url: `${metadataBaseUrl}${metadataPath}`,
            headers: metadataHeaders,
            format: {
              type: 'json',
              subject_token_field_name: 'non-existent',
            },
          },
        };
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const jsonResponse = {
          access_token: externalSubjectToken,
        };
        const scope = nock(metadataBaseUrl)
          .get(metadataPath, undefined, {
            reqheaders: metadataHeaders,
          })
          .reply(200, jsonResponse);
        const client = new IdentityPoolClient(invalidOptions);

        await assert.rejects(client.retrieveSubjectToken(), expectedError);
        scope.done();
      });

      it('should ignore headers when not provided', async () => {
        // Create options without headers.
        const urlSourcedOptionsNoHeaders = Object.assign({}, urlSourcedOptions);
        urlSourcedOptionsNoHeaders.credential_source = {
          url: urlSourcedOptions.credential_source.url,
        };
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const scope = nock(metadataBaseUrl)
          .get(metadataPath)
          .reply(200, externalSubjectToken);

        const client = new IdentityPoolClient(urlSourcedOptionsNoHeaders);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, externalSubjectToken);
        scope.done();
      });

      it('should reject with underlying on non-200 response', async () => {
        const scope = nock(metadataBaseUrl)
          .get(metadataPath, undefined, {
            reqheaders: metadataHeaders,
          })
          .reply(404);

        const client = new IdentityPoolClient(urlSourcedOptions);

        await assert.rejects(client.retrieveSubjectToken(), {
          code: '404',
        });
        scope.done();
      });
    });

    describe('getAccessToken()', () => {
      it('should resolve on retrieveSubjectToken success for text format', async () => {
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
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
                // Subject token retrieved from url should be used.
                subject_token: externalSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
              },
            },
          ])
        );
        scopes.push(
          nock(metadataBaseUrl)
            .get(metadataPath, undefined, {
              reqheaders: metadataHeaders,
            })
            .reply(200, externalSubjectToken)
        );

        const client = new IdentityPoolClient(urlSourcedOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should handle service account access token for text format', async () => {
        const now = new Date().getTime();
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(now + ONE_HOUR_IN_SECS * 1000).toISOString(),
        };
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const scopes: nock.Scope[] = [];
        scopes.push(
          nock(metadataBaseUrl)
            .get(metadataPath, undefined, {
              reqheaders: metadataHeaders,
            })
            .reply(200, externalSubjectToken),
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
                // Subject token retrieved from url should be used.
                subject_token: externalSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
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

        const client = new IdentityPoolClient(urlSourcedOptionsWithSA);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should resolve on retrieveSubjectToken success for json format', async () => {
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const jsonResponse = {
          access_token: externalSubjectToken,
        };
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
                // Subject token retrieved from url should be used.
                subject_token: externalSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
              },
            },
          ])
        );
        scopes.push(
          nock(metadataBaseUrl)
            .get(metadataPath, undefined, {
              reqheaders: metadataHeaders,
            })
            .reply(200, jsonResponse)
        );

        const client = new IdentityPoolClient(jsonRespUrlSourcedOptions);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: stsSuccessfulResponse.access_token,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should handle service account access token for json format', async () => {
        const now = new Date().getTime();
        const saSuccessResponse = {
          accessToken: 'SA_ACCESS_TOKEN',
          expireTime: new Date(now + ONE_HOUR_IN_SECS * 1000).toISOString(),
        };
        const externalSubjectToken = 'SUBJECT_TOKEN_1';
        const jsonResponse = {
          access_token: externalSubjectToken,
        };
        const scopes: nock.Scope[] = [];
        scopes.push(
          nock(metadataBaseUrl)
            .get(metadataPath, undefined, {
              reqheaders: metadataHeaders,
            })
            .reply(200, jsonResponse),
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
                // Subject token retrieved from url should be used.
                subject_token: externalSubjectToken,
                subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
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

        const client = new IdentityPoolClient(jsonRespUrlSourcedOptionsWithSA);
        const actualResponse = await client.getAccessToken();

        // Confirm raw GaxiosResponse appended to response.
        assertGaxiosResponsePresent(actualResponse);
        delete actualResponse.res;
        assert.deepStrictEqual(actualResponse, {
          token: saSuccessResponse.accessToken,
        });
        scopes.forEach(scope => scope.done());
      });

      it('should reject with retrieveSubjectToken error', async () => {
        const scope = nock(metadataBaseUrl)
          .get(metadataPath, undefined, {
            reqheaders: metadataHeaders,
          })
          .reply(404);

        const client = new IdentityPoolClient(urlSourcedOptions);

        await assert.rejects(client.getAccessToken(), {
          code: '404',
        });
        scope.done();
      });
    });
  });
});
