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
const {GoogleAuth} = require('google-auth-library');
const https = require('https');

/**
 * Acquire a client, and make a request to an API that's enabled by default.
 */
async function main() {
  const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });
  const client = await auth.getClient();
  const projectId = await auth.getProjectId();
  const url = `https://dns.googleapis.com/dns/v1/projects/${projectId}`;

  // create a new agent with keepAlive enabled
  const agent = new https.Agent({keepAlive: true});

  // use the agent as an Axios config param to make the request
  const res = await client.request({
    url,
    httpsAgent: agent,
  });
  console.log(res.data);

  // Re-use the same agent to make the next request over the same connection
  const res2 = await client.request({
    url,
    httpsAgent: agent,
  });
  console.log(res2.data);
}

main().catch(console.error);
