// Copyright 2020, Google, Inc.
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

const {OAuth2Client} = require('google-auth-library');

/**
 * Verify the ID token from IAP
 * @see https://cloud.google.com/iap/docs/signed-headers-howto
 */
async function main(idToken, projectNumber = '', projectId = '') {
  const oAuth2Client = new OAuth2Client();

  // set Audience
  let expectedAudience = null;
  if (projectId && projectNumber) {
    expectedAudience = `/projects/${projectNumber}/apps/${projectId}`;
  }

  // Verify the id_token, and access the claims.
  const response = await oAuth2Client.getIapCerts();
  const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
    idToken,
    response.certs,
    expectedAudience,
    ['https://cloud.google.com/iap']
  );
  console.log(ticket);
  if (!expectedAudience) {
    console.log(
      'Audience not verified! Supply a projectNumber and projectID to verify'
    );
  }
}

const args = process.argv.slice(2);
main(...args).catch(console.error);
