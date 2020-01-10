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

'use strict';

async function main(
  url = 'https://some.iap.url',
  targetAudience = 'iap-client-id'
) {
  // [START google_auth_idtoken]
  /**
   * TODO(developer): Uncomment these variables before running the sample.
   */
  // const url = 'https://some.iap.url';
  // const targetAudience = 'iap-client-id';

  const {GoogleAuth} = require('google-auth-library');
  const auth = new GoogleAuth();

  async function request() {
    console.info(`request ${url} with target audience ${targetAudience}`);
    const client = await auth.getIdTokenClient(targetAudience);
    const res = await client.request({url});
    console.info(res.data);
  }

  request();
  // [END google_auth_idtoken]
}

const args = process.argv.slice(2);
main(...args).catch(console.error);
