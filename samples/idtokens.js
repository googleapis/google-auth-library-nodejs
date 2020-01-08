// Copyright 2019 Google LLC
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
 * Instead of specifying the type of client you'd like to use (JWT, OAuth2, etc)
 * this library will automatically choose the right client based on the environment.
 */
const {GoogleAuth, IdTokenClient} = require('google-auth-library');

async function main() {
  const targetAudience = 'iap-client-id';
  const url = 'https://some.iap.url';
  const auth = new GoogleAuth();
  const client = auth.getIdTokenClient(targetAudience);
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
