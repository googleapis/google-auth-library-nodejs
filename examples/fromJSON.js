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

const { GoogleAuth } = require('google-auth-library');

/**
 * Instead of loading credentials from a key file, you can also provide
 * them using an environment variable and the `fromJSON` method.  This
 * is particularly convenient for systems that deploy directly from source
 * control (Heroku, App Engine, etc).
 *
 * To run this program, you can create an environment variables that contains
 * the keys:
 *
 * $ export CREDS='{
 *       "type": "service_account",
 *       "project_id": "your-project-id",
 *       "private_key_id": "your-private-key-id",
 *       "private_key": "your-private-key",
 *       "client_email": "your-client-email",
 *       "client_id": "your-client-id",
 *       "auth_uri": "https://accounts.google.com/o/oauth2/auth",
 *       "token_uri": "https://accounts.google.com/o/oauth2/token",
 *       "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
 *       "client_x509_cert_url": "your-cert-url"
 *     }'
 * $ node fromJSON.js
 *
 **/

const keysEnvVar = process.env['CREDS'];
if (!keysEnvVar) {
  throw new Error('The $CREDS environment variable was not found!');
}
const keys = JSON.parse(keysEnvVar);

async function main() {
  const auth = new GoogleAuth();
  const client = auth.fromJSON(keys);
  client.scopes = ['https://www.googleapis.com/auth/cloud-platform'];
  await client.authorize();
  const url = `https://www.googleapis.com/dns/v1/projects/${keys.project_id}`;
  const res = await client.request({ url });
  console.log(res.data);
}

main().catch(console.error);
