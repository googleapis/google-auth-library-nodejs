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

const OAuth2Client = require('../build/src/index').OAuth2Client;
const http = require('http');
const url = require('url');
const querystring = require('querystring');
const opn = require('opn');

// Download your OAuth2 configuration from the Google
const keys = require('./oauth2.keys.json');

/**
 * Start by acquiring a pre-authenticated oAuth2 client.
 */
async function main() {
  try {
    const oAuth2Client = await getAuthenticatedClient();
    // If you're going to save the refresh_token, make sure
    // to put it somewhere safe!
    console.log(`Refresh Token: ${oAuth2Client.credentials.refresh_token}`);
    console.log(`Expiration: ${oAuth2Client.credentials.expiry_date}`);
    console.log('Refreshing access token ...');
    const res = await oAuth2Client.refreshAccessToken();
    console.log(`New expiration: ${oAuth2Client.credentials.expiry_date}`);
  } catch (e) {
    console.error(e);
  }
  process.exit();
}

/**
 * Create a new OAuth2Client, and go through the OAuth2 content
 * workflow.  Return the full client to the callback.
 */
function getAuthenticatedClient() {
  return new Promise((resolve, reject) => {
    // create an oAuth client to authorize the API call.  Secrets are kept in a `keys.json` file,
    // which should be downloaded from the Google Developers Console.
    const oAuth2Client = new OAuth2Client(
      keys.web.client_id,
      keys.web.client_secret,
      keys.web.redirect_uris[0]
    );

    // Generate the url that will be used for the consent dialog.
    const authorizeUrl = oAuth2Client.generateAuthUrl({
      // To get a refresh token, you MUST set access_type to `offline`.
      access_type: 'offline',
      // set the appropriate scopes
      scope: 'https://www.googleapis.com/auth/plus.me',
      // A refresh token is only returned the first time the user
      // consents to providing access.  For illustration purposes,
      // setting the prompt to 'consent' will force this consent
      // every time, forcing a refresh_token to be returned.
      prompt: 'consent'
    });

    // Open an http server to accept the oauth callback. In this simple example, the
    // only request to our webserver is to /oauth2callback?code=<code>
    const server = http
      .createServer(async (req, res) => {
        if (req.url.indexOf('/oauth2callback') > -1) {
          // acquire the code from the querystring, and close the web server.
          const qs = querystring.parse(url.parse(req.url).query);
          console.log(`Code is ${qs.code}`);
          res.end('Authentication successful! Please return to the console.');
          server.close();

          // Now that we have the code, use that to acquire tokens.
          const r = await oAuth2Client.getToken(qs.code);
          // Make sure to set the credentials on the OAuth2 client.
          oAuth2Client.setCredentials(r.tokens);
          console.info('Tokens acquired.');
          resolve(oAuth2Client);
        }
      })
      .listen(3000, () => {
        // open the browser to the authorize url to start the workflow
        opn(authorizeUrl);
      });
  });
}

main();
