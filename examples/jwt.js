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

const JWTClient = require('../build/src/index').JWT;

/**
 * The JWT authorization is ideal for performing server-to-server
 * communication without asking for user consent.
 *
 * Suggested reading for Admin SDK users using service accounts:
 * https://developers.google.com/admin-sdk/directory/v1/guides/delegation
 **/

const keys = require('./jwt.keys.json');

async function main() {
  try {
    const client = await getJWTClient();
    const url = `https://www.googleapis.com/dns/v1/projects/${keys.project_id}`;
    const res = await client.request({ url });
    console.log(res.data);
  } catch (e) {
    console.error(e);
  }
  process.exit();
}

async function getJWTClient() {
  const client = new JWTClient(keys.client_email, null, keys.private_key, [
    'https://www.googleapis.com/auth/cloud-platform'
  ]);
  await client.authorize();
  return client;
}

main();
