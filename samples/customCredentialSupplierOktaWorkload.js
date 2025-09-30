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

const {IdentityPoolClient} = require('google-auth-library');
const {ClientCredentials} = require('simple-oauth2');
require('dotenv').config();

// Workload Identity Pool Configuration
const gcpWorkloadAudience = process.env.GCP_WORKLOAD_AUDIENCE;
const serviceAccountImpersonationUrl =
  process.env.GCP_SERVICE_ACCOUNT_IMPERSONATION_URL;
const gcsBucketName = process.env.GCS_BUCKET_NAME;

// Okta Configuration
const oktaDomain = process.env.OKTA_DOMAIN; // e.g., 'https://dev-12345.okta.com'
const oktaClientId = process.env.OKTA_CLIENT_ID; // The Client ID of your Okta M2M application
const oktaClientSecret = process.env.OKTA_CLIENT_SECRET; // The Client Secret of your Okta M2M application

// Constants for the authentication flow
const TOKEN_URL = 'https://sts.googleapis.com/v1/token';
const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt';

/**
 * A custom SubjectTokenSupplier that authenticates with Okta using the
 * Client Credentials grant flow.
 *
 * This flow is designed for machine-to-machine (M2M) authentication and
 * exchanges the application'''s client_id and client_secret for an access token.
 */
class OktaClientCredentialsSupplier {
  constructor(domain, clientId, clientSecret) {
    this.accessToken = null;
    this.expiryTime = 0;

    // Configure the simple-oauth2 client for the Client Credentials grant.
    this.oauth2Client = new ClientCredentials({
      client: {
        id: clientId,
        secret: clientSecret,
      },
      auth: {
        tokenHost: domain,
        tokenPath: '/oauth2/default/v1/token',
      },
    });
    console.log('OktaClientCredentialsSupplier initialized.');
  }

  /**
   * Main method called by the auth library. It will fetch a new token if one
   * is not already cached.
   * @returns {Promise<string>} A promise that resolves with the Okta Access token.
   */
  async getSubjectToken() {
    // Check if the current token is still valid (with a 60-second buffer).
    const isTokenValid =
      this.accessToken && Date.now() < this.expiryTime - 60 * 1000;

    if (isTokenValid) {
      console.log('[Supplier] Returning cached Okta Access token.');
      return this.accessToken;
    }

    console.log(
      '[Supplier] Token is missing or expired. Fetching new Okta Access token via Client Credentials grant...',
    );
    const {token} = await this.fetchOktaAccessToken();
    this.accessToken = token.access_token;
    this.expiryTime = token.expires_at.getTime();
    return this.accessToken;
  }

  /**
   * Performs the Client Credentials grant flow using the simple-oauth2 library.
   * @returns {Promise<object>} A promise that resolves with the token object from Okta.
   */
  async fetchOktaAccessToken() {
    try {
      // For Client Credentials, scopes are optional and define the permissions
      // the token will have. If you have custom scopes, add them here.
      const token = await this.oauth2Client.getToken({
        scope: 'gcp.test.read',
      });
      console.log(
        `[Supplier] Successfully received Access Token from Okta. Expires at ${token.token.expires_at}.`,
      );
      return token;
    } catch (error) {
      console.error(
        '[Supplier] Error fetching token from Okta:',
        error.message,
      );
      throw new Error(
        'Failed to authenticate with Okta using Client Credentials grant.',
      );
    }
  }
}

/**
 * Main function to demonstrate the custom supplier.
 */
async function main() {
  if (
    !gcpWorkloadAudience ||
    !gcsBucketName ||
    !oktaDomain ||
    !oktaClientId ||
    !oktaClientSecret
  ) {
    throw new Error(
      'Missing required environment variables. Please check your .env file.',
    );
  }

  // 1. Instantiate our custom supplier with Okta credentials.
  const oktaSupplier = new OktaClientCredentialsSupplier(
    oktaDomain,
    oktaClientId,
    oktaClientSecret,
  );

  // 2. Instantiate an IdentityPoolClient directly with the required configuration.
  // This client is specialized for workload identity federation flows.
  const client = new IdentityPoolClient({
    audience: gcpWorkloadAudience,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    token_url: TOKEN_URL,
    subject_token_supplier: oktaSupplier,
    service_account_impersonation_url: serviceAccountImpersonationUrl,
  });

  // 3. Construct the URL for the Cloud Storage JSON API to get bucket metadata.
  const bucketUrl = `https://storage.googleapis.com/storage/v1/b/${gcsBucketName}`;
  console.log(`[Test] Getting metadata for bucket: ${gcsBucketName}...`);
  console.log(`[Test] Request URL: ${bucketUrl}`);

  // 4. Use the client to make an authenticated request.
  const res = await client.request({url: bucketUrl});

  console.log('--- SUCCESS! ---');
  console.log('Successfully authenticated and retrieved bucket data:');
  console.log(JSON.stringify(res.data, null, 2));
}

main().catch(error => {
  console.error('--- FAILED ---');
  const fullError = error.response?.data || error;
  console.error(JSON.stringify(fullError, null, 2));
  process.exitCode = 1;
});
