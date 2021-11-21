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

import {GaxiosOptions} from 'gaxios';

import {AwsClientOptions} from './awsclient';
import {AwsRequestSigner} from './awsrequestsigner';
import {BaseExternalAccountClient} from './baseexternalclient';
import {RefreshOptions} from './oauth2client';

/**
 * AWS SDK v3 compatible type.
 */
export interface AwsCredentials {
  /**
   * AWS access key ID
   */
  readonly accessKeyId: string;
  /**
   * AWS secret access key
   */
  readonly secretAccessKey: string;
  /**
   * A security or session token to use with these credentials. Usually
   * present for temporary credentials.
   */
  readonly sessionToken?: string;
  /**
   * A {Date} when these credentials will no longer be accepted.
   */
  readonly expiration?: Date;
}
export type AwsCredentialsProvider =
  | AwsCredentials
  | (() => Promise<AwsCredentials>);

/**
 * AWS credentials JSON interface. This is used for AWS workloads.
 */
export interface AwsCredentialsClientOptions extends AwsClientOptions {
  awsCredentialsOptions?: {
    eagerRefreshThresholdMillis?: number;
    region?: string;
  };
}

/**
 * AWS external account client. This is used for AWS workloads, where
 * AWS STS GetCallerIdentity serialized signed requests are exchanged for
 * GCP access token.
 */
export class AwsCredentialsClient extends BaseExternalAccountClient {
  private readonly environmentId: string;
  private readonly regionalCredVerificationUrl: string;
  private awsRequestSigner: AwsRequestSigner | null;
  private readonly regionUrl?: string;
  private region: string;
  private awsEagerRefreshThresholdMillis: number;
  private cachedAwsCreds: AwsCredentials | undefined;

  /**
   * Instantiates an AwsClient instance using the provided JSON
   * object loaded from an external account credentials file.
   * An error is thrown if the credential is not a valid AWS credential.
   * @param awsCredentials AWS SDK v3 credentials
   * @param options The external account options object typically loaded
   *   from the external account JSON credential file.
   * @param additionalOptions Optional additional behavior customization
   *   options. These currently customize expiration threshold time and
   *   whether to retry on 401/403 API request errors.
   */
  constructor(
    private awsCredentials: AwsCredentialsProvider,
    options: AwsCredentialsClientOptions,
    additionalOptions?: RefreshOptions
  ) {
    super(options, additionalOptions);
    this.awsEagerRefreshThresholdMillis =
      options?.awsCredentialsOptions?.eagerRefreshThresholdMillis ??
      5 * 60 * 1000;
    this.environmentId = options.credential_source.environment_id;
    this.regionUrl = options.credential_source.region_url;
    this.regionalCredVerificationUrl =
      options.credential_source.regional_cred_verification_url;
    const match = this.environmentId?.match(/^(aws)(\d+)$/);
    if (!match || !this.regionalCredVerificationUrl) {
      throw new Error('No valid AWS "credential_source" provided');
    } else if (parseInt(match[2], 10) !== 1) {
      throw new Error(
        `aws version "${match[2]}" is not supported in the current build.`
      );
    }
    this.awsRequestSigner = null;
    this.region = options?.awsCredentialsOptions?.region ?? '';
  }

  async retrieveSubjectToken(): Promise<string> {
    if (!this.region) {
      this.region = await this.getAwsRegion();
    }
    if (!this.awsRequestSigner) {
      this.awsRequestSigner = new AwsRequestSigner(async () => {
        if (
          !this.cachedAwsCreds ||
          this.isAwsCredExpired(this.cachedAwsCreds)
        ) {
          this.cachedAwsCreds = await this.getAwsSecurityCredentials();
        }
        return {
          accessKeyId: this.cachedAwsCreds.accessKeyId,
          secretAccessKey: this.cachedAwsCreds.secretAccessKey,
          token: this.cachedAwsCreds.sessionToken,
        };
      }, this.region);
    }

    const options = await this.awsRequestSigner.getRequestOptions({
      url: this.regionalCredVerificationUrl.replace('{region}', this.region),
      method: 'POST',
    });
    const reformattedHeader: {key: string; value: string}[] = [];
    const extendedHeaders = Object.assign(
      {
        'x-goog-cloud-target-resource': this.audience,
      },
      options.headers
    );
    // Reformat header to GCP STS expected format.
    for (const key in extendedHeaders) {
      reformattedHeader.push({
        key,
        value: extendedHeaders[key],
      });
    }
    // Serialize the reformatted signed request.
    return encodeURIComponent(
      JSON.stringify({
        url: options.url,
        method: options.method,
        headers: reformattedHeader,
      })
    );
  }

  /**
   * Returns whether the provided AWS credentials are expired or not.
   * If there is no expiry time, assumes the token is not expired or expiring.
   * @param credentials The AWS credentials to check for expiration.
   * @return Whether the AWS credentials are expired or not.
   */
  private isAwsCredExpired(awsCred: AwsCredentials): boolean {
    if (!awsCred.expiration) return false;
    const now = new Date().getTime();
    return (
      now >= awsCred.expiration.getTime() - this.awsEagerRefreshThresholdMillis
    );
  }

  /**
   * @return A promise that resolves with the current AWS region.
   */
  private async getAwsRegion(): Promise<string> {
    // Priority order for region determination:
    // AWS_REGION > AWS_DEFAULT_REGION > metadata server.
    if (process.env['AWS_REGION'] || process.env['AWS_DEFAULT_REGION']) {
      return (process.env['AWS_REGION'] || process.env['AWS_DEFAULT_REGION'])!;
    }
    if (!this.regionUrl) {
      throw new Error(
        'Unable to determine AWS region due to missing ' +
          '"options.credential_source.region_url"'
      );
    }
    const opts: GaxiosOptions = {
      url: this.regionUrl,
      method: 'GET',
      responseType: 'text',
    };
    const response = await this.transporter.request<string>(opts);
    // Remove last character. For example, if us-east-2b is returned,
    // the region would be us-east-2.
    return response.data.substr(0, response.data.length - 1);
  }

  /**
   * Resolves AWS credentials from AWS SDK v3 compatible provider.
   * @return A promise that resolves with the AWS credentials.
   */
  private async getAwsSecurityCredentials(): Promise<AwsCredentials> {
    if (typeof this.awsCredentials === 'function') {
      return await this.awsCredentials();
    } else {
      return this.awsCredentials;
    }
  }
}
