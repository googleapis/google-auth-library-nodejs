'use strict';

// --- Imports ---
const {IdentityPoolClient} = require('google-auth-library');
const {Storage} = require('@google-cloud/storage');
const puppeteer = require('puppeteer');
require('dotenv').config(); // Load environment variables from .env file

// ========================================================================
// START CONFIGURATION
// ========================================================================

// These values are loaded from the .env file for security.
const GCP_WORKFORCE_POOL_ID = process.env.GCP_WORKFORCE_POOL_ID;
const GCP_WORKFORCE_PROVIDER_ID = process.env.GCP_WORKFORCE_PROVIDER_ID;
const IDP_USERNAME = process.env.IDP_USERNAME;
const IDP_PASSWORD = process.env.IDP_PASSWORD;

// --- GCP Workforce Configuration (Constructed from environment variables) ---

// The audience is the resource name of your Workforce Pool Provider.
const WORKFORCE_AUDIENCE = `//iam.googleapis.com/locations/global/workforcePools/${GCP_WORKFORCE_POOL_ID}/providers/${GCP_WORKFORCE_PROVIDER_ID}`;

// The Sign-in URL requires the full provider resource name.
const GCP_SIGN_IN_URL = `https://auth.cloud.google/signin-workforce?provider=${encodeURIComponent(
  WORKFORCE_AUDIENCE,
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
    // Made browser visible for easier debugging. Change to 'new' for headless.
    console.log('Launching visible browser for debugging...');
    const browser = await puppeteer.launch({headless: false});

    // **FIXED**: Use the correct function name for creating an incognito context in modern Puppeteer.
    const context = await browser.createIncognitoBrowserContext();
    const page = await context.newPage();

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
            // The payload is a URL-encoded string like "SAMLResponse=...&RelayState=..."
            const samlResponse = new URLSearchParams(payload).get(
              'SAMLResponse',
            );
            if (samlResponse) {
              console.log('SAML Assertion captured successfully!');
              // The SAMLResponse is already Base64 encoded by the IdP, but it's
              // URL-encoded. We decode it from URL format, then re-encode it
              // in standard Base64 for the STS API.
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
        // This is the part you would change for Azure, AWS, etc.
        await page.waitForSelector('#okta-signin-username', {timeout: 30000});
        await page.type('#okta-signin-username', this.username);
        await page.type('#okta-signin-password', this.password);
        await page.click('#okta-signin-submit');
        // --- END CUSTOMIZABLE SEQUENCE ---

        // 3. Wait for the final navigation after login.
        // The 'request' listener above will resolve the promise when it captures the SAML assertion.
        await page.waitForNavigation({
          waitUntil: 'networkidle0',
          timeout: 30000,
        });
      } catch (error) {
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
  if (!GCP_WORKFORCE_POOL_ID || !IDP_USERNAME) {
    throw new Error(
      'Required environment variables are not set. Please create and configure a .env file.',
    );
  }

  // 1. Instantiate our automated supplier with credentials.
  const automatedSupplier = new AutomatedSamlSupplier(
    IDP_USERNAME,
    IDP_PASSWORD,
  );

  // 2. Configure the IdentityPoolClient to use the supplier.
  const authClient = new IdentityPoolClient({
    audience: WORKFORCE_AUDIENCE,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    token_url: TOKEN_URL,
    subject_token_supplier: automatedSupplier,
  });

  // 3. Create a service client. The first API call will trigger the login flow.
  const storage = new Storage({authClient});

  // 4. Run a test command to verify authentication.
  console.log(
    'Successfully configured client with custom SAML assertion supplier.',
  );
  console.log('Attempting to list GCS buckets to verify authentication...');
  const [buckets] = await storage.getBuckets();

  console.log('\n--- AUTHENTICATION SUCCESSFUL ---');
  console.log('Found buckets:');
  buckets.forEach(bucket => {
    console.log(`- ${bucket.name}`);
  });
}

// Execute the test.
main().catch(err => {
  console.error('\n--- SCRIPT FAILED ---');
  console.error(err);
  process.exit(1);
});
