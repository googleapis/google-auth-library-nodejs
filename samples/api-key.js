// Copyright 2022 Google LLC
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

'use strict';

/**
 * Import the GoogleAuth library, and create a new GoogleAuth client.
 */
const {GoogleAuth} = require('google-auth-library');

/**
 * Acquire a client, and make a request to an API that's enabled by default.
 */
async function main() {
  // There are two ways to provide API key.
  // One way is using the `apiKey` option as shown below
  const auth = new GoogleAuth({
    apiKey: 'fill in the API key',
  });
  // The second way is setting the `GOOGLE_API_KEY` environment variable
  // to the API key value.
  // const auth = new GoogleAuth();

  const client = await auth.getClient();
  const url = 'https://language.googleapis.com/v1/documents:analyzeSentiment';
  const body =
    "{'document':{'type':'PLAIN_TEXT','content':'hello world'},'encodingType':'UTF8'}";
  const res = await client.request({url: url, method: 'POST', body: body});
  console.log(res.data);
}

main().catch(console.error);
