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

const {GoogleAuth} = require('google-auth-library');
const {Storage} = require('@google-cloud/storage');
const puppeteer = require('puppeteer');
require('dotenv').config();

// These values are loaded from the .env file for security.
const gcpProjectId = process.env.GCP_PROJECT_ID;
const gcpWorkforceAudience = process.env.GCP_WORKFORCE_AUDIENCE;
const serviceAccountImpersonationUrl =
  process.env.GCP_SERVICE_ACCOUNT_IMPERSONATION_URL;
const OKTA_USERNAME = process.env.OKTA_USERNAME;
const OKTA_PASSWORD = process.env.OKTA_USERNAME;
const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME; // The bucket to get metadata from.

// The Sign-in URL requires the full provider resource name (the audience).
const GCP_SIGN_IN_URL = `https://auth.cloud.google/signin-workforce?provider=${encodeURIComponent(
  gcpWorkforceAudience,
)}`;

// This is the Google STS endpoint for exchanging the SAML assertion.
const TOKEN_URL = 'https://sts.googleapis.com/v1/token';
// This subject token type tells STS that we are sending a SAML 2.0 assertion.
const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:saml2';

// The URL where the IdP posts the SAML assertion. We will intercept this.
const ACS_URL =
  'https://auth.cloud.google/signin-callback/locations/global/workforcePools/';

// ========================================================================
// END CONFIGURATION
// ========================================================================

/**
 * A non-interactive supplier that uses browser automation (Puppeteer)
 * to perform a SAML login flow and capture the assertion.
 */
class AutomatedSamlSupplier {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.samlAssertion = null;
    console.log('AutomatedSamlSupplier initialized.');
  }

  /**
   * Main method called by the auth library. Returns a cached assertion
   * or triggers the full automation flow if no valid assertion exists.
   */
  async getSubjectToken() {
    if (this.samlAssertion) {
      // In a real app, you might check for assertion expiration here.
      console.log('Returning cached SAML assertion.');
      return this.samlAssertion;
    }
    console.log('No cached assertion. Starting automated SAML login...');
    this.samlAssertion = await this.performAutomatedLogin();
    return this.samlAssertion;
  }

  /**
   * Performs the automated SP-initiated SAML login flow using Puppeteer.
   * @returns {Promise<string>} A promise that resolves with the Base64-encoded SAML assertion.
   */
  async performAutomatedLogin() {
    // Launch the browser in headless mode for terminal/CI environments.
    // For local debugging of the login flow, you can set `headless: false`
    // to watch the automation in a visible browser window.
    console.log('Launching headless browser to perform automated login...');
    const browser = await puppeteer.launch({headless: true});
    const page = await browser.newPage();

    const promise = new Promise((resolve, reject) => {
      // Intercept network requests to find the SAML Response.
      page
        .setRequestInterception(true)
        .then(() => {
          page.on('request', request => {
            if (
              request.url().startsWith(ACS_URL) &&
              request.method() === 'POST'
            ) {
              const payload = request.postData();
              const samlResponse = new URLSearchParams(payload).get(
                'SAMLResponse',
              );
              if (samlResponse) {
                console.log('SAML Assertion captured successfully!');
                const decodedSaml = decodeURIComponent(samlResponse);
                const reEncodedSaml = Buffer.from(
                  decodedSaml,
                  'base64',
                ).toString('base64');
                resolve(reEncodedSaml);
              }
            }
            request.continue();
          });

          // 1. Start the SP-initiated flow.
          console.log(`Navigating to GCP Sign-in URL: ${GCP_SIGN_IN_URL}`);
          return page.goto(GCP_SIGN_IN_URL, {waitUntil: 'networkidle0'});
        })
        .then(() => {
          // 2. The page should have automatically redirected to the Okta login page.
          console.log('Waiting for IdP login page and entering credentials...');

          // NOTE: This sequence is specific to the Okta login page. If you are using
          // a different IdP (like Azure AD), you will need to inspect its login
          // page and update the selectors and actions below accordingly.
          // --- CUSTOMIZABLE LOGIN SEQUENCE FOR OKTA ---
          return page.waitForSelector('#okta-signin-username', {
            timeout: 30000,
          });
        })
        .then(() => page.type('#okta-signin-username', this.username))
        .then(() => page.type('#okta-signin-password', this.password))
        .then(() => page.click('#okta-signin-submit'))
        .then(() => {
          // --- END CUSTOMIZABLE SEQUENCE ---

          // 3. Wait for the final navigation after login.
          return page.waitForNavigation({
            waitUntil: 'networkidle0',
            timeout: 30000,
          });
        })
        .catch(error => {
          console.error(
            'An error occurred during the browser automation.',
            error,
          );
          reject(error);
        });
    });

    // Ensure the browser is closed whether the promise resolves or rejects.
    return promise.finally(async () => {
      await browser.close();
      console.log('Browser closed.');
    });
  }
}

/**
 * Main function to run the test.
 */
async function main() {
  if (
    !gcpWorkforceAudience ||
    !serviceAccountImpersonationUrl ||
    !OKTA_USERNAME ||
    !OKTA_PASSWORD ||
    !gcpProjectId
  ) {
    throw new Error(
      'Required environment variables are not set. Please create and configure a .env file with all required values.',
    );
  }

  // 1. Instantiate our automated supplier with credentials.
  const automatedSupplier = new AutomatedSamlSupplier(
    OKTA_USERNAME,
    OKTA_PASSWORD,
  );

  // 2. Configure the main GoogleAuth client.
  // This is a more robust pattern. Instead of creating a low-level client,
  // we describe the entire authentication flow in a configuration object.
  // The GoogleAuth class will use this to construct the correct clients internally.
  const auth = new GoogleAuth({
    // By setting the project ID at the top level, we ensure it's used for all
    // API calls, including the internal call to the impersonation endpoint.
    projectId: gcpProjectId,
    credentials: {
      type: 'identity_pool',
      audience: gcpWorkforceAudience,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      token_url: TOKEN_URL,
      subject_token_supplier: automatedSupplier,
      // The impersonation URL is now read directly from the environment.
      service_account_impersonation_url: serviceAccountImpersonationUrl,
    },
  });

  // 3. Create a service client using the fully configured GoogleAuth instance.
  const storage = new Storage({auth});

  // 4. Run a new test command to verify authentication and impersonation.
  console.log('Successfully configured client for impersonation.');
  console.log(`Attempting to get metadata for bucket: ${GCS_BUCKET_NAME}...`);
  const [metadata] = await storage.bucket(GCS_BUCKET_NAME).getMetadata();

  console.log('\n--- AUTHENTICATION & IMPERSONATION SUCCESSFUL ---');
  console.log(JSON.stringify(metadata, null, 2));
  console.log(`Bucket Name: ${metadata.name}`);
  console.log(`Location: ${metadata.location}`);
  console.log(`Storage Class: ${metadata.storageClass}`);
}

// Execute the test.
main().catch(err => {
  console.error('\n--- SCRIPT FAILED ---');
  console.error(err);
  throw new Error('Test failed.');
});
