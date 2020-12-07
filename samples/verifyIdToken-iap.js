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

// sample-metadata:
//   title: Verifying ID Tokens from Identity-Aware Proxy (IAP)
//   description: Verifying the signed token from the header of an IAP-protected resource.
//   usage: node verifyIdToken-iap.js <iap-jwt> [<project-number>] [<project-id>] [<backend-service-id>]

'use strict';

const { create } = require('domain');
const {OAuth2Client} = require('google-auth-library');
const fs = require('fs');
const jwt = require('jsonwebtoken');

/**
 * Verify the ID token from IAP
 * @see https://cloud.google.com/iap/docs/signed-headers-howto
 */
function main(
  iapJwt,
  projectNumber = '',
  projectId = '',
  backendServiceId = ''
) {
  // [START iap_validate_jwt]
  /**
   * TODO(developer): Uncomment these variables before running the sample.
   */
  // const iapJwt = 'SOME_ID_TOKEN'; // JWT from the "x-goog-iap-jwt-assertion" header

  // function createJWT() {
    // Create a JWT to authenticate this device. The device will be disconnected
    // after the token expires, and will have to reconnect with a new token. The
    // audience field should always be set to the GCP project id.
  //   const token = {
  //     iat: parseInt(Date.now() / 1000),
  //     exp: parseInt(Date.now() / 1000) + 40 * 60, // 20 minutes
  //     aud: 'coleleah-sofialeon',
  //   };
  //   const privateKey = fs.readFileSync('/Users/sofialeon/gcp/google-auth-library-nodejs/samples/ec_private_testSample.pem');
  //   jwt.sign(token, privateKey, { algorithm: 'ES256' });
  //   console.log(jwt);
  //   return jwt.decode;
  // };
  //iapJwt = createJWT();
iapJwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjJlMzAyNWYyNmI1OTVmOTZlYWM5MDdjYzJiOTQ3MTQyMmJjYWViOTMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiIvcHJvamVjdHMvMjA0NTM1MTk4NzA2L2FwcHMvY29sZWxlYWgtc29maWFsZW9uIiwiYXpwIjoidGVzdC1hY2NvdW50QGNvbGVsZWFoLXNvZmlhbGVvbi5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImVtYWlsIjoidGVzdC1hY2NvdW50QGNvbGVsZWFoLXNvZmlhbGVvbi5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJleHAiOjE2MDY4NTQ1NTAsImlhdCI6MTYwNjg1MDk1MCwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTA0MTg4NDQyMjkzMjgyOTU0OTQ0In0.ncPa_rRA-_DE6hgFBeP9SIRxyt-p4vgUd2iShyN116tR9_xZTlRmZLNO15EtG8QqgJn9FvSBRadzD_cXozVjWUsG5DGAtgqbr2n2LWw4hu4Lq9vStz6eEYUo_PdQ76FW850ZPX9qWiUYPgMmQwgxhaXD4qecDaV7L5HBmoEqdfCfwbRw-XRnA1483aAiH-HhsK3PcitgFLUSHmq5Nw8a6Moj7ABXyRHOncqUrSUhYELzXHgwZY3a6EqN7d_CvJp4l_BiJKpeJQRm8UdmpGDhl2Cb563SkTsGtuO7uaEr-v1awQt6Gh-QQ1oVUNsTrnDCn4MlurhKW02OfdAffkSFGg';
  let expectedAudience = `/projects/204535198706/apps/coleleah-sofialeon`;


  const oAuth2Client = new OAuth2Client("204535198706-a44qeclp37upo4oedm3p46ksckt6k587.apps.googleusercontent.com", "3Y7PWUhBBFYwYDrj2CcGKxaG", "http://localhost:3000");

  async function verify() {
    // Verify the id_token, and access the claims.
    const response = await oAuth2Client.getIapPublicKeys();
    console.log('RESPONSE '+JSON.stringify(response.pubkeys));
    const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
      iapJwt,
      response.pubkeys,
      expectedAudience,
      ['https://cloud.google.com/iap']
    );
    // Print out the info contained in the IAP ID token
    console.log(ticket);
  }

  verify().catch(console.error);

  // [END iap_validate_jwt]
  if (!expectedAudience) {
    console.log(
      'Audience not verified! Supply a projectNumber and projectID to verify'
    );
  }
}

const args = process.argv.slice(2);
main(...args);
