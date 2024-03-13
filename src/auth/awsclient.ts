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

import {AwsRequestSigner, AwsSecurityCredentials} from './awsrequestsigner';
import {
  BaseExternalAccountClient,
  BaseExternalAccountClientOptions,
} from './baseexternalclient';
import {Headers} from './oauth2client';
import {AuthClientOptions} from './authclient';

/**
 * AWS credentials JSON interface. This is used for AWS workloads.
 */
export interface AwsClientOptions extends BaseExternalAccountClientOptions {
  credential_source: {
    environment_id: string;
    // Region can also be determined from the AWS_REGION or AWS_DEFAULT_REGION
    // environment variables.
    region_url?: string;
    // The url field is used to determine the AWS security credentials.
    // This is optional since these credentials can be retrieved from the
    // AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN
    // environment variables.
    url?: string;
    regional_cred_verification_url: string;
    // The imdsv2 session token url is used to fetch session token from AWS
    // which is later sent through headers for metadata requests. If the
    // field is missing, then session token won't be fetched and sent with
    // the metadata requests.
    // The session token is required for IMDSv2 but optional for IMDSv1
    imdsv2_session_token_url?: string;
  };
}

/**
 * Interface defining the AWS security-credentials endpoint response.
 */
interface AwsSecurityCredentialsResponse {
  Code: string;
  LastUpdated: string;
  Type: string;
  AccessKeyId: string;
  SecretAccessKey: string;
  Token: string;
  Expiration: string;
}

/**
 * AWS external account client. This is used for AWS workloads, where
 * AWS STS GetCallerIdentity serialized signed requests are exchanged for
 * GCP access token.
 */
export class AwsClient extends BaseExternalAccountClient {
  private awsCredentials: AwsSecurityCredentials | null;
  private readonly environmentId: string;
  private readonly regionUrl?: string;
  private readonly securityCredentialsUrl?: string;
  private readonly regionalCredVerificationUrl: string;
  private readonly imdsV2SessionTokenUrl?: string;
  private awsRequestSigner: AwsRequestSigner | null;
  private region: string;

  static AWS_EC2_METADATA_IPV4_ADDRESS = '169.254.169.254';
  static AWS_EC2_METADATA_IPV6_ADDRESS = 'fd00:ec2::254';

  /**
   * Instantiates an AwsClient instance using the provided JSON
   * object loaded from an external account credentials file.
   * An error is thrown if the credential is not a valid AWS credential.
   * @param options The external account options object typically loaded
   *   from the external account JSON credential file.
   * @param additionalOptions **DEPRECATED, all options are available in the
   *   `options` parameter.** Optional additional behavior customization options.
   *   These currently customize expiration threshold time and whether to retry
   *   on 401/403 API request errors.
   * @param credentials Optional AWS security credentials. If provided, these
   *   credentials will be used instead of the ones from the environment variables.
   */
  constructor(
    options: AwsClientOptions,
    additionalOptions?: AuthClientOptions,
    awsCredentials?: AwsSecurityCredentials,
  ) {
    super(options, additionalOptions);
    this.environmentId = options.credential_source.environment_id;
    // This is only required if the AWS region is not available in the
    // AWS_REGION or AWS_DEFAULT_REGION environment variables.
    this.regionUrl = options.credential_source.region_url;
    // This is only required if AWS security credentials are not available in
    // environment variables.
    this.securityCredentialsUrl = options.credential_source.url;
    this.regionalCredVerificationUrl =
      options.credential_source.regional_cred_verification_url;
    this.imdsV2SessionTokenUrl =
      options.credential_source.imdsv2_session_token_url;
    this.awsRequestSigner = null;
    this.region = '';
    this.credentialSourceType = 'aws';
    this.awsCredentials = awsCredentials || null;

    // Data validators.
    this.validateEnvironmentId();
  }

  private validateEnvironmentId() {
    const match = this.environmentId?.match(/^(aws)(\d+)$/);
    if (!match || !this.regionalCredVerificationUrl) {
      throw new Error('No valid AWS "credential_source" provided');
    } else if (parseInt(match[2], 10) !== 1) {
      throw new Error(
        `aws version "${match[2]}" is not supported in the current build.`
      );
    }
  }

  /**
   * Triggered when an external subject token is needed to be exchanged for a
   * GCP access token via GCP STS endpoint.
   * This uses the `options.credential_source` object to figure out how
   * to retrieve the token using the current environment. In this case,
   * this uses a serialized AWS signed request to the STS GetCallerIdentity
   * endpoint.
   * The logic is summarized as:
   * 1. If imdsv2_session_token_url is provided in the credential source, then
   *    fetch the aws session token and include it in the headers of the
   *    metadata requests. This is a requirement for IDMSv2 but optional
   *    for IDMSv1.
   * 2. Retrieve AWS region from availability-zone.
   * 3a. Check if AWS credentials are provided in the constructor. If not, check
   *     AWS credentials in environment variables. If still not found, get
   *     from security-credentials endpoint.
   * 3b. Get AWS credentials from security-credentials endpoint. In order
   *     to retrieve this, the AWS role needs to be determined by calling
   *     security-credentials endpoint without any argument. Then the
   *     credentials can be retrieved via: security-credentials/role_name
   * 4. Generate the signed request to AWS STS GetCallerIdentity action.
   * 5. Inject x-goog-cloud-target-resource into header and serialize the
   *    signed request. This will be the subject-token to pass to GCP STS.
   * @return A promise that resolves with the external subject token.
   */
  async retrieveSubjectToken(): Promise<string> {
    // Initialize AWS request signer if not already initialized.
    if (!this.awsRequestSigner) {
      const metadataHeaders: Headers = {};
      // Only retrieve the IMDSv2 session token if both the security credentials and region are
      // not retrievable through the environment.
      // The credential config contains all the URLs by default but clients may be running this
      // where the metadata server is not available and returning the credentials through the environment.
      // Removing this check may break them.
      if (!this.regionFromEnv && this.imdsV2SessionTokenUrl) {
        metadataHeaders['x-aws-ec2-metadata-token'] =
          await this.getImdsV2SessionToken();
      }

      this.region = await this.getAwsRegion(metadataHeaders);
      this.awsRequestSigner = new AwsRequestSigner(async () => {
        // Check provided credentials first
        if (this.awsCredentials) {
          return this.awsCredentials;
        }
        // Check environment variables for permanent credentials next.
        // https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
        if (this.securityCredentialsFromEnv) {
          return this.securityCredentialsFromEnv;
        }
        if (this.imdsV2SessionTokenUrl) {
          metadataHeaders['x-aws-ec2-metadata-token'] =
            await this.getImdsV2SessionToken();
        }
        // Since the role on a VM can change, we don't need to cache it.
        const roleName = await this.getAwsRoleName(metadataHeaders);
        // Temporary credentials typically last for several hours.
        // Expiration is returned in response.
        // Consider future optimization of this logic to cache AWS tokens
        // until their natural expiration.
        const awsCreds = await this.getAwsSecurityCredentials(
          roleName,
          metadataHeaders
        );
        return {
          accessKeyId: awsCreds.AccessKeyId,
          secretAccessKey: awsCreds.SecretAccessKey,
          token: awsCreds.Token,
        };
      }, this.region);
    }

    // Generate signed request to AWS STS GetCallerIdentity API.
    // Use the required regional endpoint. Otherwise, the request will fail.
    const options = await this.awsRequestSigner.getRequestOptions({
      url: this.regionalCredVerificationUrl.replace('{region}', this.region),
      method: 'POST',
    });
    // The GCP STS endpoint expects the headers to be formatted as:
    // [
    //   {key: 'x-amz-date', value: '...'},
    //   {key: 'Authorization', value: '...'},
    //   ...
    // ]
    // And then serialized as:
    // encodeURIComponent(JSON.stringify({
    //   url: '...',
    //   method: 'POST',
    //   headers: [{key: 'x-amz-date', value: '...'}, ...]
    // }))
    const reformattedHeader: {key: string; value: string}[] = [];
    const extendedHeaders = Object.assign(
      {
        // The full, canonical resource name of the workload identity pool
        // provider, with or without the HTTPS prefix.
        // Including this header as part of the signature is recommended to
        // ensure data integrity.
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
   * @return A promise that resolves with the IMDSv2 Session Token.
   */
  private async getImdsV2SessionToken(): Promise<string> {
    const opts: GaxiosOptions = {
      url: this.imdsV2SessionTokenUrl,
      method: 'PUT',
      responseType: 'text',
      headers: {'x-aws-ec2-metadata-token-ttl-seconds': '300'},
    };
    const response = await this.transporter.request<string>(opts);
    return response.data;
  }

  /**
   * @param headers The headers to be used in the metadata request.
   * @return A promise that resolves with the current AWS region.
   */
  private async getAwsRegion(headers: Headers): Promise<string> {
    // Priority order for region determination:
    // AWS_REGION > AWS_DEFAULT_REGION > metadata server.
    if (this.regionFromEnv) {
      return this.regionFromEnv;
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
      headers: headers,
    };
    const response = await this.transporter.request<string>(opts);
    // Remove last character. For example, if us-east-2b is returned,
    // the region would be us-east-2.
    return response.data.substr(0, response.data.length - 1);
  }

  /**
   * @param headers The headers to be used in the metadata request.
   * @return A promise that resolves with the assigned role to the current
   *   AWS VM. This is needed for calling the security-credentials endpoint.
   */
  private async getAwsRoleName(headers: Headers): Promise<string> {
    if (!this.securityCredentialsUrl) {
      throw new Error(
        'Unable to determine AWS role name due to missing ' +
          '"options.credential_source.url"'
      );
    }
    const opts: GaxiosOptions = {
      url: this.securityCredentialsUrl,
      method: 'GET',
      responseType: 'text',
      headers: headers,
    };
    const response = await this.transporter.request<string>(opts);
    return response.data;
  }

  /**
   * Retrieves the temporary AWS credentials by calling the security-credentials
   * endpoint as specified in the `credential_source` object.
   * @param roleName The role attached to the current VM.
   * @param headers The headers to be used in the metadata request.
   * @return A promise that resolves with the temporary AWS credentials
   *   needed for creating the GetCallerIdentity signed request.
   */
  private async getAwsSecurityCredentials(
    roleName: string,
    headers: Headers
  ): Promise<AwsSecurityCredentialsResponse> {
    const response =
      await this.transporter.request<AwsSecurityCredentialsResponse>({
        url: `${this.securityCredentialsUrl}/${roleName}`,
        responseType: 'json',
        headers: headers,
      });
    return response.data;
  }

  private get regionFromEnv(): string | null {
    // The AWS region can be provided through AWS_REGION or AWS_DEFAULT_REGION.
    // Only one is required.
    return (
      process.env['AWS_REGION'] || process.env['AWS_DEFAULT_REGION'] || null
    );
  }

  private get securityCredentialsFromEnv(): AwsSecurityCredentials | null {
    // Both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required.
    if (
      process.env['AWS_ACCESS_KEY_ID'] &&
      process.env['AWS_SECRET_ACCESS_KEY']
    ) {
      return {
        accessKeyId: process.env['AWS_ACCESS_KEY_ID'],
        secretAccessKey: process.env['AWS_SECRET_ACCESS_KEY'],
        token: process.env['AWS_SESSION_TOKEN'],
      };
    }
    return null;
  }
}
