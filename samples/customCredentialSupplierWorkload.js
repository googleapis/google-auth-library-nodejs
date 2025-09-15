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

const {GoogleAuth} = require('google-auth-library');
const {Storage} = require('@google-cloud/storage');

/**
 * A custom SubjectTokenSupplier that reads the third-party subject token directly
 * from an environment variable. This is the simplest method for providing a token.
 */
class CustomEnvVarSupplier {
  /**
   * This method is called by the IdentityPoolClient when it needs a subject token.
   * @returns {Promise<string>} A promise that resolves with the subject token.
   */
  async getSubjectToken() {
    console.log('[Supplier] getSubjectToken called.');

    // 1. Read the token directly from the environment variable.
    const token = process.env.THIRD_PARTY_TOKEN;

    if (!token || typeof token !== 'string') {
      throw new Error('Environment variable THIRD_PARTY_TOKEN not found.');
    }

    console.log(
      '[Supplier] Successfully retrieved subject token from environment variable.',
    );
    // The `getSubjectToken` method must return a Promise.
    return Promise.resolve(token);
  }
}

/**
 * Main function to demonstrate the custom supplier in a live environment.
 */
async function main() {
  // --- Configuration from Environment Variables ---
  const audience = process.env.GCP_WORKLOAD_AUDIENCE;
  const thirdPartyToken = process.env.THIRD_PARTY_TOKEN;
  const serviceAccountImpersonationUrl =
    process.env.GCP_SERVICE_ACCOUNT_IMPERSONATION_URL;
  const gcsBucketName = process.env.GCS_BUCKET_NAME;
  const projectId = process.env.GCP_PROJECT_ID;

  // --- Validate Environment Variables ---
  if (
    !audience ||
    !thirdPartyToken ||
    !serviceAccountImpersonationUrl ||
    !gcsBucketName ||
    !projectId
  ) {
    throw new Error(
      'Missing required environment variables. Please check your .env file or environment settings. Required: GCP_WORKLOAD_AUDIENCE, THIRD_PARTY_TOKEN, GCP_SERVICE_ACCOUNT_IMPERSONATION_URL, GCS_BUCKET_NAME, GCP_PROJECT_ID',
    );
  }

  try {
    // 1. Create an instance of our custom supplier.
    const customSupplier = new CustomEnvVarSupplier();

    // 2. Configure GoogleAuth with the full identity pool configuration.
    const auth = new GoogleAuth({
      projectId,
      credentials: {
        type: 'identity_pool',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt', // Or another appropriate type like id_token
        token_url: 'https://sts.googleapis.com/v1/token',
        subject_token_supplier: customSupplier,
        service_account_impersonation_url: serviceAccountImpersonationUrl,
      },
    });

    // 3. Create a service client (e.g., Storage) using the configured auth instance.
    const storage = new Storage({auth});

    // 4. Make an API call to verify the end-to-end authentication flow.
    console.log(`[Test] Getting metadata for bucket: ${gcsBucketName}...`);
    const [metadata] = await storage.bucket(gcsBucketName).getMetadata();

    console.log('\n--- SUCCESS ---');
    console.log('Successfully authenticated and retrieved bucket metadata:');
    console.log(JSON.stringify(metadata, null, 2));
  } catch (error) {
    console.error('\n--- FAILED ---');
    console.error('An error occurred during the process:', error.message);
  }
}

main();
