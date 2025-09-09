'use strict';
Object.defineProperty(exports, '__esModule', {value: true});

// --- Imports ---
const {AwsClient} = require('google-auth-library');
const {fromNodeProviderChain} = require('@aws-sdk/credential-providers');
const {Storage} = require('@google-cloud/storage');

// ========================================================================
// START CONFIGURATION: !! REPLACE WITH YOUR VALUES !!
// ========================================================================

// These values can be found by running the gcloud CLI command:
// gcloud iam workload-identity-pools create-cred-config \
//     projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$WORKLOAD_POOL_ID/providers/$PROVIDER_ID \
//     --service-account="$EMAIL" \
//     --output-format="json" \
//     --aws

/**
 * The Audience for the GCP Workload Identity Pool Provider.
 */
const GCP_AUDIENCE =
  '//iam.googleapis.com/projects/654269145772/locations/global/workloadIdentityPools/pjiyer-byoid-testing/providers/aws-pid1';

/**
 * The URL for impersonating the target Google Cloud Service Account.
 */
const SA_IMPERSONATION_URL =
  'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/byoid-test@cicpclientproj.iam.gserviceaccount.com:generateAccessToken';

/**
 * The AWS Region your workload is running in. This is required by the AWS SDK
 * to sign the request properly.
 */
const AWS_REGION = 'us-east-2'; // Example: 'us-east-1'

// ========================================================================
// END CONFIGURATION
// ========================================================================

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
    if (!region || region.includes('YOUR_')) {
      throw new Error(
        'AWS_REGION constant must be set at the top of the script.',
      );
    }
    this.region = region;
  }

  /**
   * Returns the AWS region. This is required for signing the AWS request.
   */
  async getAwsRegion(context) {
    return this.region;
  }

  /**
   * Retrieves AWS security credentials using the AWS SDK's default provider chain.
   */
  async getAwsSecurityCredentials(context) {
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
      token: awsCredentials.sessionToken, // Will be undefined if using static keys, which is fine
    };

    return awsSecurityCredentials;
  }
}

/**
 * Main function to run the test.
 */
async function main() {
  if (
    GCP_AUDIENCE.includes('YOUR_') ||
    SA_IMPERSONATION_URL.includes('YOUR_')
  ) {
    throw new Error(
      'Please update the placeholder constants (GCP_AUDIENCE, SA_IMPERSONATION_URL) at the top of the script with your real values.',
    );
  }

  // 1. Instantiate the custom supplier.
  const customSupplier = new CustomAwsSupplier(AWS_REGION);

  // 2. Configure the AwsClient options using the constants.
  const clientOptions = {
    audience: GCP_AUDIENCE,
    subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
    service_account_impersonation_url: SA_IMPERSONATION_URL,

    // ** This is the key part: Inject the custom supplier **
    aws_security_credentials_supplier: customSupplier,
  };

  // 3. Create the auth client and the service client (Storage).
  const authClient = new AwsClient(clientOptions);
  const storage = new Storage({authClient});

  const bucketName = 'pjiyer-byoid-test-gcs-bucket';

  // 4. Run the test command to verify authentication.
  console.log('Successfully configured client with custom AWS supplier.');
  console.log(
    `Attempting to get metadata for GCS bucket "${bucketName}" to verify authentication...`,
  );
  const [metadata] = await storage.bucket(bucketName).getMetadata();

  console.log('Authentication Successful! Bucket metadata:');
  console.log(JSON.stringify(metadata, null, 2));

  console.log('Done.');
}

// Execute the test.
main().catch(err => {
  console.error('\n--- TEST FAILED ---');
  console.error(err);
  throw new Error('test failed');
});
