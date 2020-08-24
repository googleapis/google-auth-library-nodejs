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

import {GaxiosOptions} from 'gaxios';

import {Headers} from './oauth2client';
import {Crypto, createCrypto, fromArrayBufferToHex} from '../crypto/crypto';

type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'HEAD'
  | 'DELETE'
  | 'CONNECT'
  | 'OPTIONS'
  | 'TRACE';

/** Interface defining the AWS authorization header map for signed requests. */
interface AwsAuthHeaderMap {
  amzDate: string;
  authorizationHeader: string;
  canonicalQuerystring: string;
}

/**
 * Interface defining AWS security credentials.
 * These are either determined from AWS security_credentials endpoint or
 * AWS environment variables.
 */
interface AwsSecurityCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  token?: string;
}

/** AWS Signature Version 4 signing algorithm identifier.  */
const AWS_ALGORITHM = 'AWS4-HMAC-SHA256';
/**
 * The termination string for the AWS credential scope value as defined in
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 */
const AWS_REQUEST_TYPE = 'aws4_request';

/**
 * Implements an AWS API request signer based on the AWS Signature Version 4
 * signing process.
 * https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
export class AwsRequestSigner {
  private readonly crypto: Crypto;

  /**
   * Instantiates an AWS API handler used to send authenticated signed
   * requests to AWS APIs based on the AWS Signature Version 4 signing process.
   * This also provides a mechanism to generate the signed request without
   * sending it.
   * @param getCredentials A mechanism to retrieve AWS security credentials
   *   when needed.
   * @param region The AWS region to use.
   */
  constructor(
    private readonly getCredentials: () => Promise<AwsSecurityCredentials>,
    private readonly region: string
  ) {
    this.crypto = createCrypto();
  }

  /**
   * Generates the signed request for the provided HTTP request for calling
   * an AWS API. This follows the steps described at:
   * https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
   * @param amzOptions The AWS request options that need to be signed.
   * @return A promise that resolves with the GaxiosOptions containing the
   *   signed HTTP request parameters.
   */
  async getRequestOptions(amzOptions: GaxiosOptions): Promise<GaxiosOptions> {
    if (!amzOptions.url) {
      throw new Error('"url" is required in "amzOptions"');
    }
    // Stringify JSON requests. This will be set in the request body of the
    // generated signed request.
    const requestPayloadData =
      typeof amzOptions.data === 'object'
        ? JSON.stringify(amzOptions.data)
        : amzOptions.data;
    const url = amzOptions.url;
    const method = amzOptions.method || 'GET';
    const requestPayload = amzOptions.body || requestPayloadData;
    const additionalAmzHeaders = amzOptions.headers;
    const awsSecurityCredentials = await this.getCredentials();
    const uri = new URL(url);
    const headerMap = await generateAuthenticationHeaderMap(
      this.crypto,
      uri.host,
      uri.pathname,
      uri.search.substr(1),
      method,
      this.region,
      awsSecurityCredentials,
      requestPayload,
      additionalAmzHeaders
    );
    // Append additional optional headers, eg. X-Amz-Target, Content-Type, etc.
    const headers: {[key: string]: string} = Object.assign(
      {
        'x-amz-date': headerMap.amzDate,
        Authorization: headerMap.authorizationHeader,
        host: uri.host,
      },
      additionalAmzHeaders || {}
    );
    if (awsSecurityCredentials.token) {
      Object.assign(headers, {
        'x-amz-security-token': awsSecurityCredentials.token,
      });
    }
    const awsSignedReq: GaxiosOptions = {
      url,
      method: method,
      headers,
    };

    if (typeof requestPayload !== 'undefined') {
      awsSignedReq.body = requestPayload;
    }

    return awsSignedReq;
  }
}

/**
 * Creates the HMAC-SHA256 hash of the provided message using the
 * provided key.
 *
 * @param key The HMAC-SHA256 key to use.
 * @param msg The message to hash.
 * @return The computed hash bytes.
 */
async function sign(
  crypto: Crypto,
  key: string | ArrayBuffer,
  msg: string
): Promise<ArrayBuffer> {
  return await crypto.signWithHmacSha256(key, msg);
}

/**
 * Calculates the signature for AWS Signature Version 4.
 * Based on:
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 *
 * @param key The AWS secret access key.
 * @param dateStamp The '%Y%m%d' date format.
 * @param region The AWS region.
 * @param serviceName The AWS service name, eg. sts.
 * @return The signing key bytes.
 */
async function getSigningKey(
  crypto: Crypto,
  key: string,
  dateStamp: string,
  region: string,
  serviceName: string
): Promise<ArrayBuffer> {
  const kDate = await sign(crypto, `AWS4${key}`, dateStamp);
  const kRegion = await sign(crypto, kDate, region);
  const kService = await sign(crypto, kRegion, serviceName);
  const kSigning = await sign(crypto, kService, 'aws4_request');
  return kSigning;
}

/**
 * Generates the authentication header map needed for generating the AWS
 * Signature Version 4 signed request.
 *
 * @param accessKeyId The AWS access key ID.
 * @param secretAccessKey The AWS secret access kye.
 * @param token The AWS token.
 * @return The AWS authentication header map which constitutes of the following
 *   components: amz-date, authorization header and canonical query string.
 */
async function generateAuthenticationHeaderMap(
  crypto: Crypto,
  host: string,
  canonicalUri: string,
  canonicalQuerystring: string,
  method: HttpMethod,
  region: string,
  securityCredentials: AwsSecurityCredentials,
  requestPayload = '',
  additionalAmzHeaders: Headers = {}
): Promise<AwsAuthHeaderMap> {
  // iam.amazonaws.com host => iam service.
  // sts.us-east-2.amazonaws.com => sts service.
  const serviceName = host.split('.')[0];
  const now = new Date();
  // Format: '%Y%m%dT%H%M%SZ'.
  const amzDate = now
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.[0-9]+/, '');
  // Format: '%Y%m%d'.
  const dateStamp = now.toISOString().replace(/[-]/g, '').replace(/T.*/, '');

  // Change all additional headers to be lower case.
  const reformattedAdditionalAmzHeaders: Headers = {};
  Object.keys(additionalAmzHeaders).forEach(key => {
    reformattedAdditionalAmzHeaders[key.toLowerCase()] =
      additionalAmzHeaders[key];
  });
  // Add AWS token if available.
  if (securityCredentials.token) {
    reformattedAdditionalAmzHeaders['x-amz-security-token'] =
      securityCredentials.token;
  }
  // Header keys need to be sorted alphabetically.
  const amzHeaders = Object.assign(
    {
      host,
      'x-amz-date': amzDate,
    },
    reformattedAdditionalAmzHeaders
  );
  let canonicalHeaders = '';
  const signedHeadersList = Object.keys(amzHeaders).sort();
  signedHeadersList.forEach(key => {
    canonicalHeaders += `${key}:${amzHeaders[key]}\n`;
  });
  const signedHeaders = signedHeadersList.join(';');

  const payloadHash = await crypto.sha256DigestHex(requestPayload);
  // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  const canonicalRequest =
    `${method}\n` +
    `${canonicalUri}\n` +
    `${canonicalQuerystring}\n` +
    `${canonicalHeaders}\n` +
    `${signedHeaders}\n` +
    `${payloadHash}`;
  const credentialScope = `${dateStamp}/${region}/${serviceName}/${AWS_REQUEST_TYPE}`;
  // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
  const stringToSign =
    `${AWS_ALGORITHM}\n` +
    `${amzDate}\n` +
    `${credentialScope}\n` +
    (await crypto.sha256DigestHex(canonicalRequest));
  // https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
  const signingKey = await getSigningKey(
    crypto,
    securityCredentials.secretAccessKey,
    dateStamp,
    region,
    serviceName
  );
  const signature = await sign(crypto, signingKey, stringToSign);
  // https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
  const authorizationHeader =
    `${AWS_ALGORITHM} Credential=${securityCredentials.accessKeyId}/` +
    `${credentialScope}, SignedHeaders=${signedHeaders}, ` +
    `Signature=${fromArrayBufferToHex(signature)}`;

  return {
    amzDate,
    authorizationHeader,
    canonicalQuerystring,
  };
}
