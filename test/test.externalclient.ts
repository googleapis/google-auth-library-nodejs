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
import {AwsClient} from '../src/auth/awsclient';
import {IdentityPoolClient} from '../src/auth/identitypoolclient';
import {ExternalAccountClient} from '../src/auth/externalclient';
import {getAudience, getTokenUrl} from './externalclienthelper';

const serviceAccountKeys = {
  type: 'service_account',
  project_id: 'PROJECT_ID',
  private_key_id: 'PRIVATE_KEY_ID',
  private_key:
    '-----BEGIN PRIVATE KEY-----\n' + 'REDACTED\n-----END PRIVATE KEY-----\n',
  client_email: '$PROJECT_ID@appspot.gserviceaccount.com',
  client_id: 'CLIENT_ID',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://accounts.google.com/o/oauth2/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/' +
    'PROEJCT_ID%40appspot.gserviceaccount.com',
};

const fileSourcedOptions = {
  type: 'external_account',
  audience: getAudience(),
  subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  token_url: getTokenUrl(),
  credential_source: {
    file: './test/fixtures/external-subject-token.txt',
  },
};

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
  audience: getAudience(),
  subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
  token_url: getTokenUrl(),
  credential_source: awsCredentialSource,
};

describe('ExternalAccountClient', () => {
  describe('Constructor', () => {
    it('should throw on initialization', () => {
      assert.throws(() => {
        return new ExternalAccountClient();
      }, /ExternalAccountClients should be initialized via/);
    });
  });

  describe('fromJSON()', () => {
    const refreshOptions = {
      eagerRefreshThresholdMillis: 1000 * 10,
      forceRefreshOnFailure: true,
    };

    const invalidWorkforceIdentityPoolClientAudiences = [
      '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc',
      '//iam.googleapis.com/projects/123/locations/global/workforcepools//providers/oidc',
      '//iam.googleapis.com/projects/123/locations/global/workforcepools/pool/providers/oidc',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/providers/oidc',
      '//iam.googleapis.com/projects/locations/global/workforcePools/providers/azure',
      '//iam.googleapis.com/projects//locations/global/workforcePools/providers/azure',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/pool/providers',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/pool/providers/',
      '//iam.googleapis.com/projects/123/locations//workforcepools/pool/providers/azure',
      '//iam.googleapis.com/projects/123/locations/workforcepools/pool/providers/azure',
    ];

    const invalidWorkforceAwsClientAudiences = [
      '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws',
      '//iam.googleapis.com/projects/123/locations/global/workforcepools//providers/aws',
      '//iam.googleapis.com/projects/123/locations/global/workforcepools/pool/providers/aws',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/providers/aws',
      '//iam.googleapis.com/projects/locations/global/workforcePools/providers/aws',
      '//iam.googleapis.com/projects//locations/global/workforcePools/providers/aws',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/pool/providers',
      '//iam.googleapis.com/projects/123/locations/global/workforcePools/pool/providers/',
      '//iam.googleapis.com/projects/123/locations//workforcepools/pool/providers/aws',
      '//iam.googleapis.com/projects/123/locations/workforcepools/pool/providers/aws',
    ];

    it('should return IdentityPoolClient on IdentityPoolClientOptions', () => {
      const expectedClient = new IdentityPoolClient(fileSourcedOptions);

      assert.deepStrictEqual(
        ExternalAccountClient.fromJSON(fileSourcedOptions),
        expectedClient
      );
    });

    it('should return IdentityPoolClient with expected RefreshOptions', () => {
      const expectedClient = new IdentityPoolClient(
        fileSourcedOptions,
        refreshOptions
      );

      assert.deepStrictEqual(
        ExternalAccountClient.fromJSON(fileSourcedOptions, refreshOptions),
        expectedClient
      );
    });

    it('should return AwsClient on AwsClientOptions', () => {
      const expectedClient = new AwsClient(awsOptions);

      assert.deepStrictEqual(
        ExternalAccountClient.fromJSON(awsOptions),
        expectedClient
      );
    });

    it('should return AwsClient with expected RefreshOptions', () => {
      const expectedClient = new AwsClient(awsOptions, refreshOptions);

      assert.deepStrictEqual(
        ExternalAccountClient.fromJSON(awsOptions, refreshOptions),
        expectedClient
      );
    });

    it('should return IdentityPoolClient with expected workforce configs', () => {
      const validWorkforceIdentityPoolClientAudiences = [
        '//iam.googleapis.com/projects/123/locations/global/workforcePools/workforcePools/providers/provider',
        '//iam.googleapis.com/projects/workforcePool/locations/global/workforcePools/pool/providers/provider',
        '//iam.googleapis.com/projects/projectId/locations/global/workforcePools/workloadPools/providers/oidc',
        '//iam.googleapis.com/projects/projectId/locations/global/workforcePools/workloadPools/providers/azure',
      ];
      const workforceFileSourcedOptions = Object.assign(
        {},
        fileSourcedOptions as any
      );
      workforceFileSourcedOptions.workforce_pool_user_project =
        'work_force_pool_user_project';
      workforceFileSourcedOptions.subject_token_type =
        'urn:ietf:params:oauth:token-type:id_token';
      for (const validWorkforceIdentityPoolClientAudience of validWorkforceIdentityPoolClientAudiences) {
        workforceFileSourcedOptions.audience =
          validWorkforceIdentityPoolClientAudience;
        const expectedClient = new IdentityPoolClient(
          workforceFileSourcedOptions
        );

        assert.deepStrictEqual(
          ExternalAccountClient.fromJSON(workforceFileSourcedOptions),
          expectedClient
        );
      }
    });

    it('should return AwsClient with expected workforce configs', () => {
      const validWorkforceAwsClientAudiences = [
        '//iam.googleapis.com/projects/123/locations/global/workforcePools/workforcePools/providers/provider',
        '//iam.googleapis.com/projects/workforcePool/locations/global/workforcePools/pool/providers/provider',
        '//iam.googleapis.com/projects/projectId/locations/global/workforcePools/workloadPools/providers/aws',
      ];
      const workforceAwsOptions = Object.assign({}, awsOptions as any);
      workforceAwsOptions.workforce_pool_user_project =
        'work_force_pool_user_project';
      workforceAwsOptions.subject_token_type =
        'urn:ietf:params:oauth:token-type:aws4_request';
      for (const validWorkforceAwsClientAudience of validWorkforceAwsClientAudiences) {
        workforceAwsOptions.audience = validWorkforceAwsClientAudience;
        const expectedClient = new AwsClient(workforceAwsOptions);

        assert.deepStrictEqual(
          ExternalAccountClient.fromJSON(workforceAwsOptions),
          expectedClient
        );
      }
    });

    invalidWorkforceIdentityPoolClientAudiences.forEach(
      invalidWorkforceIdentityPoolClientAudience => {
        const workforceIdentityPoolClientInvalidOptions = Object.assign(
          {},
          fileSourcedOptions as any
        );
        workforceIdentityPoolClientInvalidOptions.workforce_pool_user_project =
          'work_force_pool_user_project';
        workforceIdentityPoolClientInvalidOptions.subject_token_type =
          'urn:ietf:params:oauth:token-type:id_token';
        it(`should throw given audience ${invalidWorkforceIdentityPoolClientAudience} with user project defined in IdentityPoolClientOptions`, () => {
          workforceIdentityPoolClientInvalidOptions.audience =
            invalidWorkforceIdentityPoolClientAudience;

          assert.throws(() => {
            return ExternalAccountClient.fromJSON(
              workforceIdentityPoolClientInvalidOptions
            );
          });
        });
      }
    );

    invalidWorkforceAwsClientAudiences.forEach(
      invalidWorkforceAwsClientAudience => {
        const workforceAwsClientInvalidOptions = Object.assign(
          {},
          awsOptions as any
        );
        workforceAwsClientInvalidOptions.workforce_pool_user_project =
          'work_force_pool_user_project';
        workforceAwsClientInvalidOptions.subject_token_type =
          'urn:ietf:params:aws:token-type:aws4_request';
        it(`should throw given audience ${invalidWorkforceAwsClientAudience} with user project defined in AwsClientOptions`, () => {
          workforceAwsClientInvalidOptions.audience =
            invalidWorkforceAwsClientAudience;

          assert.throws(() => {
            return ExternalAccountClient.fromJSON(
              workforceAwsClientInvalidOptions
            );
          });
        });
      }
    );

    it('should return null when given non-ExternalAccountClientOptions', () => {
      assert(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ExternalAccountClient.fromJSON(serviceAccountKeys as any) === null
      );
    });

    it('should throw when given invalid ExternalAccountClient', () => {
      const invalidOptions = Object.assign({}, fileSourcedOptions);
      delete invalidOptions.credential_source;

      assert.throws(() => {
        return ExternalAccountClient.fromJSON(invalidOptions);
      });
    });

    it('should throw when given invalid IdentityPoolClient', () => {
      const invalidOptions = Object.assign({}, fileSourcedOptions);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (invalidOptions as any).credential_source = {};

      assert.throws(() => {
        return ExternalAccountClient.fromJSON(invalidOptions);
      });
    });

    it('should throw when given invalid AwsClientOptions', () => {
      const invalidOptions = Object.assign({}, awsOptions);
      invalidOptions.credential_source.environment_id = 'invalid';

      assert.throws(() => {
        return ExternalAccountClient.fromJSON(invalidOptions);
      });
    });
  });
});
