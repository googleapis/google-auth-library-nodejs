// Copyright 2020 Google LLC
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

// sample-metadata:
//   title: ID Tokens for Cloud Run
//   description: Requests a Cloud Run URL with an ID Token.
//   usage: node idtokens-cloudrun.js <url> [<target-audience>]

'use strict';

async function main(
  url = 'https://service-1234-uc.a.run.app',
  targetAudience = null
) {
  // [START google_auth_idtoken_cloudrun]
  /**
   * TODO(developer): Uncomment these variables before running the sample.
   */
  // const url = 'https://YOUR_CLOUD_RUN_URL.run.app';
  const {GoogleAuth} = require('google-auth-library');
  const auth = new GoogleAuth();

  async function request() {
    if (!targetAudience) {
      // Use the request URL hostname as the target audience for Cloud Run requests
      const {URL} = require('url');
      targetAudience = new URL(url).origin;
    }
    console.info(
      `request Cloud Run ${url} with target audience ${targetAudience}`
    );
    const client = await auth.getIdTokenClient(targetAudience);
    const res = await client.request({url});
    console.info(res.data);
  }

  request();
  // [END google_auth_idtoken_cloudrun]
}

const args = process.argv.slice(2);
main(...args).catch(console.error);
