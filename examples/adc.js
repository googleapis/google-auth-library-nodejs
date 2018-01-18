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
 * and use a client via Application Default Credentials. This is the
 * easiest way to get started.
 */

/**
 * Import the GoogleAuth library, and create a new GoogleAuth client.
 */
const { auth } = require('google-auth-library');

/**
 * Acquire a client, and make a request to an API that's enabled by default.
 */
async function main() {
  // Acquire a client and the projectId based on the environment. This method looks
  // for the GCLOUD_PROJECT and GOOGLE_APPLICATION_CREDENTIALS environment variables.
  const res = await auth.getApplicationDefault();
  const client = res.credential;
  client.scopes = ['https://www.googleapis.com/auth/cloud-platform'];
  const url = `https://www.googleapis.com/dns/v1/projects/${res.projectId}`;
  const res2 = await client.request({ url });
  console.log(res2.data);
}

main().catch(console.error);
