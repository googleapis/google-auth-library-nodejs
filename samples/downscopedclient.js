// Copyright 2021, Google, LLC.
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

/**
 * Imports the Google Auth and Google Cloud libraries.
 */
const {
  OAuth2Client,
  GoogleAuth,
  DownscopedClient,
} = require('google-auth-library');
const {Storage} = require('@google-cloud/storage');

// TODO(developer): Replace these variables before running the sample.
// Make sure the bucket and object exists in your project.
// The Cloud Storage bucket name.
const bucketName = 'your-gcs-bucket-name';
// The Cloud Storage object name that resides in the specified bucket.
const objectName = 'your-gcs-object-name';

/**
 * This example shows creating a downscopedClient, and using that client to
 * define oauth2Client refresh access token logic. Then the oauth2Client is
 * used to define a cloud storage object and call GCS APIs.
 */
async function main() {
  // Define CAB object.
  const cab = {
    accessBoundary: {
      accessBoundaryRules: [
        {
          availableResource: `//storage.googleapis.com/projects/_/buckets/${bucketName}`,
          availablePermissions: ['inRole:roles/storage.objectAdmin'],
        },
      ],
    },
  };

  const oauth2Client = new OAuth2Client();
  const googleAuth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });
  const projectId = await googleAuth.getProjectId();
  // Obtain an authenticated client.
  const client = await googleAuth.getClient();
  // Use the client to generate a DownscopedClient.
  const cabClient = new DownscopedClient(client, cab);
  // Define refreshHandler of oauth2Client using cabClient to refresh tokens.
  oauth2Client.refreshHandler = async () => {
    const refreshedAccessToken = await cabClient.getAccessToken();
    return {
      access_token: refreshedAccessToken.token,
      expiry_date: refreshedAccessToken.expirationTime,
    };
  };

  const storageOptions = {
    projectId,
    authClient: {
      getCredentials: async () => {
        Promise.reject();
      },
      request: opts => {
        return oauth2Client.request(opts);
      },
      sign: () => {
        Promise.reject('unsupported');
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
  const downloadFile = await storage
    .bucket(bucketName)
    .file(objectName)
    .download();
  console.log(downloadFile.toString('utf8'));
}

main().catch(console.error);
