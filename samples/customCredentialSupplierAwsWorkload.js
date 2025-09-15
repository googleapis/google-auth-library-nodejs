// Copyright 2025 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict';

// --- Imports ---
const {AwsClient} = require('google-auth-library');
const {fromNodeProviderChain} = require('@aws-sdk/credential-providers');
const {Storage} = require('@google-cloud/storage');

/**
 * Custom AWS Security Credentials Supplier.
 *
 * This implementation resolves AWS credentials using the default Node provider
 * chain from the AWS SDK. This allows fetching credentials from environment
 * variables, shared credential files (~/.aws/credentials), or IAM roles
 * for service accounts (IRSA) in EKS, etc.
 */
class CustomAwsSupplier {
  /**
   * @param {string} region The AWS region the workload is running in.
   */
  constructor(region) {
    this.region = region;
  }

  /**
   * Returns the AWS region. This is required for signing the AWS request.
   */
  async getAwsRegion(_context) {
    return this.region;
  }

  /**
   * Retrieves AWS security credentials using the AWS SDK's default provider chain.
   */
  async getAwsSecurityCredentials(_context) {
    console.log('CustomAwsSupplier: Resolving AWS credentials...');

    // Use the official AWS SDK provider chain. This will find credentials
    // from Env variables, shared config, EC2 metadata, EKS OIDC, etc.
    const awsCredentialsProvider = fromNodeProviderChain();
    const awsCredentials = await awsCredentialsProvider();

    if (!awsCredentials.accessKeyId || !awsCredentials.secretAccessKey) {
      throw new Error(
        'Unable to resolve AWS credentials from the node provider chain. ' +
          'Ensure your AWS CLI is configured, or AWS environment variables (like AWS_ACCESS_KEY_ID) are set.',
      );
    }

    console.log(
      `CustomAwsSupplier: Found AWS Access Key ID: ${awsCredentials.accessKeyId}`,
    );

    // Map the AWS SDK format to the google-auth-library format.
    const awsSecurityCredentials = {
      accessKeyId: awsCredentials.accessKeyId,
      secretAccessKey: awsCredentials.secretAccessKey,
      token: awsCredentials.sessionToken,
    };

    return awsSecurityCredentials;
  }
}

/**
 * Main function to run the test.
 */
async function main() {
  // --- Configuration from Environment Variables ---
  const gcpAudience = process.env.GCP_WORKLOAD_AUDIENCE;
  const saImpersonationUrl = process.env.GCP_SERVICE_ACCOUNT_IMPERSONATION_URL;
  const awsRegion = process.env.AWS_REGION;
  const bucketName = process.env.GCS_BUCKET_NAME;

  // --- Validate Environment Variables ---
  if (!gcpAudience || !saImpersonationUrl || !awsRegion || !bucketName) {
    throw new Error(
      'Missing required environment variables. Please check your .env file or environment settings. Required: GCP_WORKLOAD_AUDIENCE, GCP_SERVICE_ACCOUNT_IMPERSONATION_URL, AWS_REGION, GCS_BUCKET_NAME',
    );
  }

  console.log(
    '--- Running Custom AWS Workload Credential Supplier Example ---',
  );

  // 1. Instantiate the custom supplier.
  const customSupplier = new CustomAwsSupplier(awsRegion);

  // 2. Configure the AwsClient options using the constants.
  const clientOptions = {
    audience: gcpAudience,
    subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
    service_account_impersonation_url: saImpersonationUrl,
    aws_security_credentials_supplier: customSupplier,
  };

  // 3. Create the auth client and the service client (Storage).
  const authClient = new AwsClient(clientOptions);
  const storage = new Storage({authClient});

  // 4. Run the test command to verify authentication.
  console.log('Successfully configured client with custom AWS supplier.');
  console.log(
    `Attempting to get metadata for GCS bucket "${bucketName}" to verify authentication...`,
  );
  const [metadata] = await storage.bucket(bucketName).getMetadata();

  console.log('\n--- SUCCESS ---');
  console.log('Successfully authenticated and retrieved bucket metadata:');
  console.log(JSON.stringify(metadata, null, 2));
}

// Execute the test.
main().catch(err => {
  console.error('\n--- FAILED ---');
  console.error(err);
  throw new Error('Test failed.');
});
