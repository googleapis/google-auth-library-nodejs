// Copyright 2017, Google, Inc.
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
 * This is an example of using the GoogleAuth object to acquire
 * and use a client via Application Default Credentials. It also uses
 * a single httpAgent with keepAlive set, so a single connection can be
 * used across multiple requests.
 */

/**
 * Import the GoogleAuth library, and create a new GoogleAuth client.
 */
const { auth } = require('google-auth-library');
const https = require('https');

/**
 * Acquire a client, and make a request to an API that's enabled by default.
 */
async function main() {
  const adc = await getADC();
  const url = `https://www.googleapis.com/dns/v1/projects/${adc.projectId}`;

  // create a new agent with keepAlive enabled
  const agent = new https.Agent({ keepAlive: true });

  // use the agent as an Axios config param to make the request
  const res = await adc.client.request({
    url,
    httpsAgent: agent
  });
  console.log(res.data);

  // Re-use the same agent to make the next request over the same connection
  const res2 = await adc.client.request({
    url,
    httpsAgent: agent
  });
  console.log(res2.data);
}

/**
 * Instead of specifying the type of client you'd like to use (JWT, OAuth2, etc)
 * this library will automatically choose the right client based on the environment.
 */
async function getADC() {
  // Acquire a client and the projectId based on the environment. This method looks
  // for the GCLOUD_PROJECT and GOOGLE_APPLICATION_CREDENTIALS environment variables.
  const res = await auth.getApplicationDefault();
  let client = res.credential;

  // The createScopedRequired method returns true when running on GAE or a local developer
  // machine. In that case, the desired scopes must be passed in manually. When the code is
  // running in GCE or a Managed VM, the scopes are pulled from the GCE metadata server.
  // See https://cloud.google.com/compute/docs/authentication for more information.
  if (client.createScopedRequired && client.createScopedRequired()) {
    // Scopes can be specified either as an array or as a single, space-delimited string.
    const scopes = ['https://www.googleapis.com/auth/cloud-platform'];
    client = client.createScoped(scopes);
  }
  return {
    client: client,
    projectId: res.projectId
  };
}

main().catch(console.error);
