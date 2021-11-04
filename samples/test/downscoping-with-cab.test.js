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

// Prerequisites:
// Make sure to run the setup in samples/scripts/downscoping-with-cab-setup.js
// and copy the logged constant strings (bucketName, objectName1 and
// objectName2) into this file before running this test suite.
// Once that is done, this test can be run indefinitely.
//
// The only requirement for this test suite to run is to set the environment
// variable GOOGLE_APPLICATION_CREDENTIALS to point to the same service account
// keys used in the setup script.
//
// The test does the following:
// 1. Define a cab rule.
// 2. Create a downscopedClient with rule and client from ADC. (the broker)
// 3. Create a oauth2Client and set refresh access token logic using the downscopedClient. (the consumer)
// 4. Initiate a GCS object with oauth2Client and call storage APIs.

const {
  GoogleAuth,
  DownscopedClient,
  OAuth2Client,
} = require('google-auth-library');
const {Storage} = require('@google-cloud/storage');
const {assert} = require('chai');
const {describe, it} = require('mocha');

const bucketName = 'cab-int-bucket-brd3qlsuok';
const objectName1 = 'cab-first-"brd3qlsuok.txt';
const objectName2 = 'cab-second-"brd3qlsuok.txt';
const CONTENT = 'first';

describe('samples for downscoping with cab', () => {
  const googleAuth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });
  // Define the Credential Access Boundary object.
  const cab = {
    // Define the access boundary.
    accessBoundary: {
      // Define the single access boundary rule.
      accessBoundaryRules: [
        {
          availableResource: `//storage.googleapis.com/projects/_/buckets/${bucketName}`,
          // Downscoped credentials will have readonly access to the resource.
          availablePermissions: ['inRole:roles/storage.objectViewer'],
          // Only objects starting with the specified prefix string in the object name
          // will be allowed read access.
          availabilityCondition: {
            expression:
              "resource.name.startsWith('projects/_/buckets/" +
              `${bucketName}/objects/${objectName1}')`,
          },
        },
      ],
    },
  };

  it('should only have access to the object specified in the cab rule', async () => {
    const projectId = await googleAuth.getProjectId();
    const errorMessage =
      'does not have storage.objects.get access to the Google Cloud Storage object.';

    // Create the OAuth credentials (the consumer).
    const oauth2Client = new OAuth2Client();
    // We are defining a refresh handler instead of a one-time access
    // token/expiry pair.
    // This will allow the consumer to obtain new downscoped tokens on
    // demand every time a token is expired, without any additional code
    // changes.
    oauth2Client.refreshHandler = async () => {
      // Obtain an authenticated client via ADC.
      const client = await googleAuth.getClient();

      // Create a DownscopedClient with the credential access boundary defined
      // above. This client will only be able to access the file contents of
      // the specified object.
      const cabClient = new DownscopedClient(client, cab);

      // The common pattern of usage is to have a token broker pass the
      // downscoped short-lived access tokens to a token consumer via some
      // secure authenticated channel. For illustration purposes, we are
      // generating the downscoped token locally.
      const refreshedAccessToken = await cabClient.getAccessToken();
      return {
        access_token: refreshedAccessToken.token,
        expiry_date: refreshedAccessToken.expirationTime,
      };
    };

    const storageOptions = {
      projectId,
      authClient: {
        sign: () => {
          Promise.reject('unsupported');
        },
        getCredentials: async () => {
          Promise.reject();
        },
        request: opts => {
          return oauth2Client.request(opts);
        },
        authorizeRequest: async opts => {
          opts = opts || {};
          const url = opts.url || opts.uri;
          const headers = await oauth2Client.getRequestHeaders(url);
          opts.headers = Object.assign(opts.headers || {}, headers);
          return opts;
        },
      },
    };

    const storage = new Storage(storageOptions);
    // Test object1 can be downloaded.
    const downloadFile = await storage
      .bucket(bucketName)
      .file(objectName1)
      .download();
    assert.strictEqual(downloadFile.toString('utf8').includes(CONTENT), true);

    // Test object2 download fails due to no access.
    try {
      await storage.bucket(bucketName).file(objectName2).download();
    } catch (e) {
      assert.strictEqual(e.message.includes(errorMessage), true);
    }
  });
});
