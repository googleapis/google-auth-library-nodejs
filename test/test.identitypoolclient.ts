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
import {describe, it} from 'mocha';
import * as fs from 'fs';
import * as nock from 'nock';

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
  });

  describe('for file-sourced subject tokens', () => {
    describe('retrieveSubjectToken()', () => {
      it('should resolve when the file is found', async () => {
        const client = new IdentityPoolClient(fileSourcedOptions);
        const subjectToken = await client.retrieveSubjectToken();

        assert.deepEqual(subjectToken, fileSubjectToken);
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
      it('should resolve on retrieveSubjectToken success', async () => {
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

      it('should handle service account access token', async () => {
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
      it('should resolve on success', async () => {
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
      it('should resolve on retrieveSubjectToken success', async () => {
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

      it('should handle service account access token', async () => {
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
