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

// [START iap_validate_jwt]
const {OAuth2Client} = require('google-auth-library');

/**
 * Verify the ID token from IAP
 * @see https://cloud.google.com/iap/docs/signed-headers-howto
 */
async function main(
  iapJwt,
  projectNumber = '',
  projectId = '',
  backendServiceId = ''
) {
  // set Audience
  let expectedAudience = null;
  if (projectNumber && projectId) {
    // Expected Audience for App Engine.
    expectedAudience = `/projects/${projectNumber}/apps/${projectId}`;
  } else if (projectNumber && backendServiceId) {
    // Expected Audience for Compute Engine
    expectedAudience = `/projects/${projectNumber}/global/backendServices/${backendServiceId}`;
  }

  const oAuth2Client = new OAuth2Client();

  // Verify the id_token, and access the claims.
  const response = await oAuth2Client.getIapPublicKeys();
  const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
    iapJwt,
    response.pubkeys,
    expectedAudience,
    ['https://cloud.google.com/iap']
  );

  // Print out the info contained in the IAP ID token
  console.log(ticket);

  if (!expectedAudience) {
    console.log(
      'Audience not verified! Supply a projectNumber and projectID to verify'
    );
  }
}
// [END iap_validate_jwt]

const args = process.argv.slice(2);
main(...args).catch(console.error);
