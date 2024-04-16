// Copyright 2024 Google LLC
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

import {ExternalAccountSupplierContext} from './baseexternalclient';
import {Gaxios, GaxiosOptions} from 'gaxios';
import {Transporter} from '../transporters';
import {AwsSecurityCredentialsSupplier} from './awsclient';
import {AwsSecurityCredentials} from './awsrequestsigner';
import {Headers} from './oauth2client';

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
 * Interface defining the options used to build a {@link DefaultAwsSecurityCredentialsSupplier}.
 */
export interface DefaultAwsSecurityCredentialsSupplierOptions {
  /**
   * The URL to call to retrieve the active AWS region.
   **/
  regionUrl?: string;
  /**
   * The URL to call to retrieve AWS security credentials.
   **/
  securityCredentialsUrl?: string;
  /**
   ** The URL to call to retrieve the IMDSV2 session token.
   **/
  imdsV2SessionTokenUrl?: string;
  /**
   * Additional Gaxios options to use when making requests to the AWS metadata
   * endpoints.
   */
  additionalGaxiosOptions?: GaxiosOptions;
}

/**
 * Internal AWS security credentials supplier implementation used by {@link AwsClient}
 * when a credential source is provided instead of a user defined supplier.
 * The logic is summarized as:
 * 1. If imdsv2_session_token_url is provided in the credential source, then
 *    fetch the aws session token and include it in the headers of the
 *    metadata requests. This is a requirement for IDMSv2 but optional
 *    for IDMSv1.
 * 2. Retrieve AWS region from availability-zone.
 * 3a. Check AWS credentials in environment variables. If not found, get
 *     from security-credentials endpoint.
 * 3b. Get AWS credentials from security-credentials endpoint. In order
 *     to retrieve this, the AWS role needs to be determined by calling
 *     security-credentials endpoint without any argument. Then the
 *     credentials can be retrieved via: security-credentials/role_name
 * 4. Generate the signed request to AWS STS GetCallerIdentity action.
 * 5. Inject x-goog-cloud-target-resource into header and serialize the
 *    signed request. This will be the subject-token to pass to GCP STS.
 */
export class DefaultAwsSecurityCredentialsSupplier
  implements AwsSecurityCredentialsSupplier
{
  private readonly regionUrl?: string;
  private readonly securityCredentialsUrl?: string;
  private readonly imdsV2SessionTokenUrl?: string;
  private readonly additionalGaxiosOptions?: GaxiosOptions;

  /**
   * Instantiates a new DefaultAwsSecurityCredentialsSupplier using information
   * from the credential_source stored in the ADC file.
   * @param opts The default aws security credentials supplier options object to
   *   build the supplier with.
   */
  constructor(opts: DefaultAwsSecurityCredentialsSupplierOptions) {
    this.regionUrl = opts.regionUrl;
    this.securityCredentialsUrl = opts.securityCredentialsUrl;
    this.imdsV2SessionTokenUrl = opts.imdsV2SessionTokenUrl;
    this.additionalGaxiosOptions = opts.additionalGaxiosOptions;
  }

  /**
   * Returns the active AWS region. This first checks to see if the region
   * is available as an environment variable. If it is not, then the supplier
   * will call the region URL.
   * @param context {@link ExternalAccountSupplierContext} from the calling
   *   {@link AwsClient}, contains the requested audience and subject token type
   *   for the external account identity.
   * @return A promise that resolves with the AWS region string.
   */
  async getAwsRegion(context: ExternalAccountSupplierContext): Promise<string> {
    // Priority order for region determination:
    // AWS_REGION > AWS_DEFAULT_REGION > metadata server.
    if (this.#regionFromEnv) {
      return this.#regionFromEnv;
    }

    const metadataHeaders: Headers = {};
    if (!this.#regionFromEnv && this.imdsV2SessionTokenUrl) {
      metadataHeaders['x-aws-ec2-metadata-token'] =
        await this.#getImdsV2SessionToken(context.transporter);
    }
    if (!this.regionUrl) {
      throw new Error(
        'Unable to determine AWS region due to missing ' +
          '"options.credential_source.region_url"'
      );
    }
    const opts: GaxiosOptions = {
      ...this.additionalGaxiosOptions,
      url: this.regionUrl,
      method: 'GET',
      responseType: 'text',
      headers: metadataHeaders,
    };
    const response = await context.transporter.request<string>(opts);
    // Remove last character. For example, if us-east-2b is returned,
    // the region would be us-east-2.
    return response.data.substr(0, response.data.length - 1);
  }

  /**
   * Returns AWS security credentials. This first checks to see if the credentials
   * is available as environment variables. If it is not, then the supplier
   * will call the security credentials URL.
   * @param context {@link ExternalAccountSupplierContext} from the calling
   *   {@link AwsClient}, contains the requested audience and subject token type
   *   for the external account identity.
   * @return A promise that resolves with the AWS security credentials.
   */
  async getAwsSecurityCredentials(
    context: ExternalAccountSupplierContext
  ): Promise<AwsSecurityCredentials> {
    // Check environment variables for permanent credentials first.
    // https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
    if (this.#securityCredentialsFromEnv) {
      return this.#securityCredentialsFromEnv;
    }

    const metadataHeaders: Headers = {};
    if (this.imdsV2SessionTokenUrl) {
      metadataHeaders['x-aws-ec2-metadata-token'] =
        await this.#getImdsV2SessionToken(context.transporter);
    }
    // Since the role on a VM can change, we don't need to cache it.
    const roleName = await this.#getAwsRoleName(
      metadataHeaders,
      context.transporter
    );
    // Temporary credentials typically last for several hours.
    // Expiration is returned in response.
    // Consider future optimization of this logic to cache AWS tokens
    // until their natural expiration.
    const awsCreds = await this.#retrieveAwsSecurityCredentials(
      roleName,
      metadataHeaders,
      context.transporter
    );
    return {
      accessKeyId: awsCreds.AccessKeyId,
      secretAccessKey: awsCreds.SecretAccessKey,
      token: awsCreds.Token,
    };
  }

  /**
   * @param transporter The transporter to use for requests.
   * @return A promise that resolves with the IMDSv2 Session Token.
   */
  async #getImdsV2SessionToken(
    transporter: Transporter | Gaxios
  ): Promise<string> {
    const opts: GaxiosOptions = {
      ...this.additionalGaxiosOptions,
      url: this.imdsV2SessionTokenUrl,
      method: 'PUT',
      responseType: 'text',
      headers: {'x-aws-ec2-metadata-token-ttl-seconds': '300'},
    };
    const response = await transporter.request<string>(opts);
    return response.data;
  }

  /**
   * @param headers The headers to be used in the metadata request.
   * @param transporter The transporter to use for requests.
   * @return A promise that resolves with the assigned role to the current
   *   AWS VM. This is needed for calling the security-credentials endpoint.
   */
  async #getAwsRoleName(
    headers: Headers,
    transporter: Transporter | Gaxios
  ): Promise<string> {
    if (!this.securityCredentialsUrl) {
      throw new Error(
        'Unable to determine AWS role name due to missing ' +
          '"options.credential_source.url"'
      );
    }
    const opts: GaxiosOptions = {
      ...this.additionalGaxiosOptions,
      url: this.securityCredentialsUrl,
      method: 'GET',
      responseType: 'text',
      headers: headers,
    };
    const response = await transporter.request<string>(opts);
    return response.data;
  }

  /**
   * Retrieves the temporary AWS credentials by calling the security-credentials
   * endpoint as specified in the `credential_source` object.
   * @param roleName The role attached to the current VM.
   * @param headers The headers to be used in the metadata request.
   * @param transporter The transporter to use for requests.
   * @return A promise that resolves with the temporary AWS credentials
   *   needed for creating the GetCallerIdentity signed request.
   */
  async #retrieveAwsSecurityCredentials(
    roleName: string,
    headers: Headers,
    transporter: Transporter | Gaxios
  ): Promise<AwsSecurityCredentialsResponse> {
    const response = await transporter.request<AwsSecurityCredentialsResponse>({
      ...this.additionalGaxiosOptions,
      url: `${this.securityCredentialsUrl}/${roleName}`,
      responseType: 'json',
      headers: headers,
    });
    return response.data;
  }

  get #regionFromEnv(): string | null {
    // The AWS region can be provided through AWS_REGION or AWS_DEFAULT_REGION.
    // Only one is required.
    return (
      process.env['AWS_REGION'] || process.env['AWS_DEFAULT_REGION'] || null
    );
  }

  get #securityCredentialsFromEnv(): AwsSecurityCredentials | null {
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
