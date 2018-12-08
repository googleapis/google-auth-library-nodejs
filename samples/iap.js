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

const {JWT} = require('google-auth-library');

/**
 * The JWT authorization is ideal for performing server-to-server
 * communication without asking for user consent.
 *
 * Suggested reading for Admin SDK users using service accounts:
 * https://developers.google.com/admin-sdk/directory/v1/guides/delegation
 **/

const keys = require('./jwt.keys.json');
const oauth2Keys = require('./iap.keys.json');

async function main() {
  const clientId = oauth2Keys.web.client_id;
  const client = new JWT({
    email: keys.client_email,
    key: keys.private_key,
    additionalClaims: {target_audience: clientId},
  });
  const url = `https://iap-demo-dot-el-gato.appspot.com`;
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
