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

/*
sample-metadata:
  title       : ID Tokens for Cloud Run
  description : Requests a Cloud Run URL with an ID Token.
  usage       : node idtokens-cloudrun.js <url> [<target-audience>] <method> [<data>]
*/

// NOTE: 'data' is an optional parameter and will be passed only 
// if needed by the request method as the request body.

'use strict';

/* TODO(developer): 
  - Pass parameters as per your requirements. (Description below)
  - Parameters for Cloud Run endpoint:
    1. url             : URL for your Cloud Run Application
    2. targetAudience  : Your Target Audience
    3. method          : Request Method => GET | POST | ...
    4. data            : Request Body (as per requirement)
*/

// Modify default parameters as per your requirements (if needed)
function main(
  url = 'https://service-1234-uc.a.run.app',
  targetAudience = null,
  method = 'GET',
  data
) {

  // Google Auth Library Initialization
  const {GoogleAuth} = require('google-auth-library');
  const auth = new GoogleAuth();

  async function request() {

    if (!targetAudience) {
      // Using request URL hostname as the target audience for Cloud Run requests
      const {URL} = require('url');
      targetAudience = new URL(url).origin;
    }
    console.info(
      `request Cloud Run ${url} with target audience ${targetAudience}`
    );
    // Fetch access token and use it for authenticated Cloud Run requests.
    const client = await auth.getIdTokenClient(targetAudience);

    let res;
    if (method === 'GET') {
      res = await client.request({url});
    } else if (method === 'POST') {
      res = await client.request({url,data,method});
    }

    console.info(res.data);

  }

  request().catch(err => {
    console.error(err.message);
    process.exitCode = 1;
  });
  // [END google_auth_idtoken_cloudrun]
}

const args = process.argv.slice(2);
main(...args);
