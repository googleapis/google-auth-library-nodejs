// Copyright 2021 Google LLC
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

// Make sure to run the setup in samples/scripts/externalclient-setup.js
// and copy the logged audience string to the AUDIENCE constant in this file
// before running this test suite. Once that is done, this test can be run
// indefinitely.
// The only requirement for this test suite is to set the environment
// variable GOOGLE_APPLICATION_CREDENTIALS to point to the same service account
// keys used in the setup script.
//
// This script follows the following logic:
// Use the service account keys to generate a Google ID token using the
// iamcredentials generateIdToken API, using the default STS audience.
// This will use the service account client ID as the sub field of the token.
//
// This OIDC token will be used as the external subject token to be exchanged
// for a Google access token via GCP STS endpoint and then to impersonate the
// original service account key. This is abstracted by the GoogleAuth library.
//
// The test suite will run tests for file-sourced and url-sourced credentials.
// In both cases, the same Google OIDC token is used as the underlying subject
// token.
// For each test, a sample script is run in a child process with
// GOOGLE_APPLICATION_CREDENTIALS environment variable pointing to a temporary
// workload identity pool credentials configuration. A Cloud API is called in
// the process and the expected output is confirmed.

const cp = require('child_process');
const {assert} = require('chai');
const {describe, it, before, afterEach} = require('mocha');
const fs = require('fs');
const {promisify} = require('util');
const {GoogleAuth} = require('google-auth-library');
const os = require('os');
const path = require('path');
const http = require('http');

/**
 * Runs the provided command using asynchronous child_process.exec.
 * Unlike execSync, this works with another local HTTP server running in the
 * background.
 * @param {string} cmd The actual command string to run.
 * @param {*} opts The optional parameters for child_process.exec.
 * @return {Promise<string>} A promise that resolves with a string
 *   corresponding with the terminal output.
 */
const execAsync = async (cmd, opts) => {
  const {stdout, stderr} = await exec(cmd, opts);
  return stdout + stderr;
};

/**
 * Generates a Google ID token using the iamcredentials generateIdToken API.
 * https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oidc
 *
 * @param {GoogleAuth} auth The GoogleAuth instance.
 * @param {string} aud The Google ID token audience.
 * @param {string} clientEmail The service account client email.
 * @return {Promise<string>} A promise that resolves with the generated Google
 *   ID token.
 */
const generateGoogleIdToken = async (auth, aud, clientEmail) => {
  // roles/iam.serviceAccountTokenCreator role needed.
  const response = await auth.request({
    url:
      'https://iamcredentials.googleapis.com/v1/' +
      `projects/-/serviceAccounts/${clientEmail}:generateIdToken`,
    method: 'POST',
    data: {
      audience: aud,
      includeEmail: true,
    },
  });
  return response.data.token;
};

/**
 * Generates a random string of the specified length, optionally using the
 * specified alphabet.
 *
 * @param {number} length The length of the string to generate.
 * @return {string} A random string of the provided length.
 */
const generateRandomString = length => {
  const chars = [];
  const allowedChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  while (length > 0) {
    chars.push(
      allowedChars.charAt(Math.floor(Math.random() * allowedChars.length))
    );
    length--;
  }
  return chars.join('');
};

// The STS audience. Copy from output of
// samples/scripts/externalclient-setup.js.
const AUDIENCE =
  '//iam.googleapis.com/projects/1046198160504/locations/global/' +
  'workloadIdentityPools/pool-ersg6slz1q/providers/oidc-ersg6slz1q';
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const unlink = promisify(fs.unlink);
const exec = promisify(cp.exec);
const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;

describe('samples for external-account', () => {
  const aud = AUDIENCE;
  let httpServer;
  let clientEmail;
  let oidcToken;
  const port = 8088;
  const suffix = generateRandomString(10);
  const configFilePath = path.join(os.tmpdir(), `config-${suffix}.json`);
  const oidcTokenFilePath = path.join(os.tmpdir(), `token-${suffix}.txt`);
  const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });

  before(async () => {
    const keys = JSON.parse(await readFile(keyFile, 'utf8'));
    clientEmail = keys.client_email;

    // Generate the Google OIDC token. This will be used as the external
    // subject token for the following tests.
    oidcToken = await generateGoogleIdToken(auth, aud, clientEmail);
  });

  afterEach(async () => {
    // Delete temporary files.
    if (fs.existsSync(configFilePath)) {
      await unlink(configFilePath);
    }
    if (fs.existsSync(oidcTokenFilePath)) {
      await unlink(oidcTokenFilePath);
    }
    // Close any open http servers.
    if (httpServer) {
      httpServer.close();
    }
  });

  it('should acquire ADC for file-sourced creds', async () => {
    // Create file-sourced configuration JSON file.
    // The created OIDC token will be used as the subject token and will be
    // retrieved from a file location.
    const config = {
      type: 'external_account',
      audience: aud,
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      token_url: 'https://sts.googleapis.com/v1beta/token',
      service_account_impersonation_url:
        'https://iamcredentials.googleapis.com/v1/projects/' +
        `-/serviceAccounts/${clientEmail}:generateAccessToken`,
      credential_source: {
        file: oidcTokenFilePath,
      },
    };
    await writeFile(oidcTokenFilePath, oidcToken);
    await writeFile(configFilePath, JSON.stringify(config));

    // Run sample script with GOOGLE_APPLICATION_CREDENTIALS envvar
    // pointing to the temporarily created configuration file.
    const output = await execAsync('node adc', {
      env: {
        GOOGLE_APPLICATION_CREDENTIALS: configFilePath,
      },
    });
    // Confirm expected script output.
    assert.match(output, /DNS Info:/);
  });

  it('should acquire ADC for url-sourced creds', async () => {
    // Create url-sourced configuration JSON file.
    // The created OIDC token will be used as the subject token and will be
    // retrieved from a local server.
    const config = {
      type: 'external_account',
      audience: aud,
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      token_url: 'https://sts.googleapis.com/v1beta/token',
      service_account_impersonation_url:
        'https://iamcredentials.googleapis.com/v1/projects/' +
        `-/serviceAccounts/${clientEmail}:generateAccessToken`,
      credential_source: {
        url: `http://localhost:${port}/token`,
        headers: {
          'my-header': 'some-value',
        },
        format: {
          type: 'json',
          subject_token_field_name: 'access_token',
        },
      },
    };
    await writeFile(configFilePath, JSON.stringify(config));
    // Start local metadata server. This will expose a /token
    // endpoint to return the OIDC token in JSON format.
    httpServer = http.createServer((req, res) => {
      if (req.url === '/token' && req.method === 'GET') {
        // Confirm expected header is passed along the request.
        if (req.headers['my-header'] === 'some-value') {
          res.setHeader('Content-Type', 'application/json');
          res.writeHead(200);
          res.end(
            JSON.stringify({
              access_token: oidcToken,
            })
          );
        } else {
          res.setHeader('Content-Type', 'application/json');
          res.writeHead(400);
          res.end(
            JSON.stringify({
              error: 'missing-header',
            })
          );
        }
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({error: 'Resource not found'}));
      }
    });
    await new Promise(resolve => {
      httpServer.listen(port, resolve);
    });

    // Run sample script with GOOGLE_APPLICATION_CREDENTIALS environment
    // variable pointing to the temporarily created configuration file.
    const output = await execAsync('node adc', {
      env: {
        GOOGLE_APPLICATION_CREDENTIALS: configFilePath,
      },
    });
    // Confirm expected script output.
    assert.match(output, /DNS Info:/);
  });
});
