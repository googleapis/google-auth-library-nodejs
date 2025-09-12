'use strict';

// --- Imports ---
const {GoogleAuth} = require('google-auth-library'); // **CHANGED**: Import GoogleAuth
const {Storage} = require('@google-cloud/storage');
const puppeteer = require('puppeteer');
require('dotenv').config(); // Load environment variables from .env file

// ========================================================================
// START CONFIGURATION
// ========================================================================

// These values are loaded from the .env file for security.
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID; // Your target Google Cloud Project ID.
const GCP_WORKFORCE_POOL_ID = process.env.GCP_WORKFORCE_POOL_ID;
const GCP_WORKFORCE_PROVIDER_ID = process.env.GCP_WORKFORCE_PROVIDER_ID;
const IDP_USERNAME = process.env.IDP_USERNAME;
const IDP_PASSWORD = process.env.IDP_PASSWORD;
const TARGET_SERVICE_ACCOUNT = process.env.TARGET_SERVICE_ACCOUNT; // Email of the SA to impersonate.
const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME; // The bucket to get metadata from.

// --- GCP Workforce Configuration (Constructed from environment variables) ---

// The audience is the resource name of your Workforce Pool Provider.
const WORKFORCE_AUDIENCE = `//iam.googleapis.com/locations/global/workforcePools/${GCP_WORKFORCE_POOL_ID}/providers/${GCP_WORKFORCE_PROVIDER_ID}`;

// The Sign-in URL requires the full provider resource name. This is the starting point.
const GCP_SIGN_IN_URL = `https://auth.cloud.google/signin-workforce?provider=${encodeURIComponent(
  WORKFORCE_AUDIENCE,
)}`;

// This is the Google STS endpoint for exchanging the SAML assertion.
const TOKEN_URL = 'https://sts.googleapis.com/v1/token';
// This subject token type tells STS that we are sending a SAML 2.0 assertion.
const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:saml2';

// This is the URL the auth library will use to impersonate the service account.
const SERVICE_ACCOUNT_IMPERSONATION_URL = `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${TARGET_SERVICE_ACCOUNT}:generateAccessToken`;

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
    // For documentation, it's helpful to see the browser. For production CI/CD, change to 'new'.
    console.log('Launching visible browser for debugging...');
    const browser = await puppeteer.launch({headless: false});
    const page = await browser.newPage();

    return new Promise(async (resolve, reject) => {
      try {
        // Intercept network requests to find the SAML Response.
        await page.setRequestInterception(true);
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
              const reEncodedSaml = Buffer.from(decodedSaml, 'base64').toString(
                'base64',
              );
              resolve(reEncodedSaml);
            }
          }
          request.continue();
        });

        // 1. Start the SP-initiated flow.
        console.log(`Navigating to GCP Sign-in URL: ${GCP_SIGN_IN_URL}`);
        await page.goto(GCP_SIGN_IN_URL, {waitUntil: 'networkidle0'});

        // 2. The page should have automatically redirected to the Okta login page.
        console.log('Waiting for IdP login page and entering credentials...');

        // --- CUSTOMIZABLE LOGIN SEQUENCE FOR OKTA ---
        await page.waitForSelector('#okta-signin-username', {timeout: 30000});
        await page.type('#okta-signin-username', this.username);
        await page.type('#okta-signin-password', this.password);
        await page.click('#okta-signin-submit');
        // --- END CUSTOMIZABLE SEQUENCE ---

        // 3. Wait for the final navigation after login.
        await page.waitForNavigation({
          waitUntil: 'networkidle0',
          timeout: 30000,
        });
      } catch (error) {
        console.error(
          'An error occurred during the browser automation.',
          error,
        );
        reject(error);
      } finally {
        await browser.close();
        console.log('Browser closed.');
      }
    });
  }
}

/**
 * Main function to run the test.
 */
async function main() {
  if (
    !GCP_WORKFORCE_POOL_ID ||
    !IDP_USERNAME ||
    !GCP_PROJECT_ID ||
    !TARGET_SERVICE_ACCOUNT ||
    !GCS_BUCKET_NAME
  ) {
    throw new Error(
      'Required environment variables are not set. Please create and configure a .env file with all required values.',
    );
  }

  // 1. Instantiate our automated supplier with credentials.
  const automatedSupplier = new AutomatedSamlSupplier(
    IDP_USERNAME,
    IDP_PASSWORD,
  );

  // 2. **CHANGED**: Configure the main GoogleAuth client directly.
  // This is a more robust pattern. Instead of creating a low-level client,
  // we describe the entire authentication flow in a configuration object.
  // The GoogleAuth class will use this to construct the correct clients internally.
  const auth = new GoogleAuth({
    // By setting the project ID at the top level, we ensure it's used for all
    // API calls, including the internal call to the impersonation endpoint.
    // This definitively solves the "unregistered callers" error.
    projectId: GCP_PROJECT_ID,
    credentials: {
      type: 'identity_pool',
      audience: WORKFORCE_AUDIENCE,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      token_url: TOKEN_URL,
      subject_token_supplier: automatedSupplier,
      service_account_impersonation_url: SERVICE_ACCOUNT_IMPERSONATION_URL,
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
  process.exit(1);
});
