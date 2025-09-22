// Copyright 2025 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// you may not use this file except in compliance with the License.
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
const {Gaxios} = require('gaxios');
require('dotenv').config();

// --- Configuration from Environment Variables ---
// These variables should be set in a .env file for local testing.

// Workforce Pool User Project
const workforcePoolUserProject = process.env.WORKFORCE_POOL_USER_PROJECT;
const gcpWorkforceAudience = process.env.GCP_WORKFORCE_AUDIENCE;
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
 * exchanges the application's client_id and client_secret for an access token.
 *
 * This is the recommended secure pattern for service-to-service communication.
 */
class OktaClientCredentialsSupplier {
  constructor(domain, clientId, clientSecret) {
    this.oktaTokenUrl = `${domain}/oauth2/default/v1/token`;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.accessToken = null;
    this.expiryTime = 0;
    this.gaxios = new Gaxios();
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
    const {accessToken, expiresIn} = await this.fetchOktaAccessToken();
    this.accessToken = accessToken;
    // Calculate the absolute expiry time in milliseconds.
    this.expiryTime = Date.now() + expiresIn * 1000;
    return this.accessToken;
  }

  /**
   * Performs the Client Credentials grant flow by making a POST request to Okta's token endpoint.
   * @returns {Promise<string>} A promise that resolves with the Access Token from Okta.
   */
  async fetchOktaAccessToken() {
    const params = new URLSearchParams();
    params.append('grant_type', 'client_credentials');
    // For Client Credentials, scopes are optional and define the permissions
    // the token will have. If you have custom scopes, add them here.
    params.append('scope', 'gcp.test.read');

    // The client_id and client_secret are sent in a Basic Auth header.
    const authHeader =
      'Basic ' +
      Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');

    try {
      const response = await this.gaxios.request({
        url: this.oktaTokenUrl,
        method: 'POST',
        headers: {
          Authorization: authHeader,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        data: params.toString(),
      });

      const {access_token, expires_in} = response.data;

      if (access_token && expires_in) {
        console.log(
          `[Supplier] Successfully received Access Token from Okta. Expires in ${expires_in} seconds.`,
        );
        return {accessToken: access_token, expiresIn: expires_in};
      } else {
        throw new Error(
          'Access token or expires_in not found in Okta response.',
        );
      }
    } catch (error) {
      console.error(
        '[Supplier] Error fetching token from Okta:',
        error.response?.data || error.message,
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
    !workforcePoolUserProject ||
    !gcpWorkforceAudience ||
    !serviceAccountImpersonationUrl ||
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
  // This client is specialized for workforce/workload identity federation flows.
  const client = new IdentityPoolClient({
    // For workforce pools, this project is used for quota and billing purposes.
    // It's passed as the `x-goog-user-project` header.
    workforcePoolUserProject: workforcePoolUserProject,
    // The full configuration for the identity pool token exchange.
    audience: gcpWorkforceAudience,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    token_url: TOKEN_URL,
    subject_token_supplier: oktaSupplier,
    service_account_impersonation_url: serviceAccountImpersonationUrl,
  });

  // 3. Construct the URL for the Cloud Storage JSON API to get bucket metadata.
  const url = `https://storage.googleapis.com/storage/v1/b/${gcsBucketName}`;
  console.log(`[Test] Getting metadata for bucket: ${gcsBucketName}...`);
  console.log(`[Test] Request URL: ${url}`);

  // 4. Use the client to make an authenticated request.
  const res = await client.request({url});

  console.log('\n--- SUCCESS! ---');
  console.log('Successfully authenticated and retrieved bucket data:');
  console.log(JSON.stringify(res.data, null, 2));
}

main().catch(error => {
  console.error('\n--- FAILED ---');
  const fullError = error.response?.data || error;
  console.error(JSON.stringify(fullError, null, 2));
  process.exitCode = 1;
});
