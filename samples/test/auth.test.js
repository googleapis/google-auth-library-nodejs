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

const cp = require('child_process');
const {assert} = require('chai');
const {describe, it} = require('mocha');
const {auth} = require('google-auth-library');

const execSync = (cmd, opts) => {
  return cp.execSync(cmd, Object.assign({encoding: 'utf-8'}, opts));
};

const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;
const ZONE = 'us-central1-a';
const TARGET_AUDIENCE = 'iap.googleapis.com';

describe('auth samples', () => {
  it.skip('should authenticate explicitly', async () => {
    const output = execSync(`node authenticateExplicit`);

    assert.match(output, /Listed all storage buckets./);
  });

  it('should authenticate implicitly with adc', async () => {
    const projectId = await auth.getProjectId();

    const output = execSync(
      `node authenticateImplicitWithAdc ${projectId} ${ZONE}`
    );

    assert.match(output, /Listed all storage buckets./);
  });

  it('should get id token from metadata server', async () => {
    const output = execSync(
      'node idTokenFromMetadataServer https://www.google.com'
    );

    assert.match(output, /Generated ID token./);
  });

  it('should get id token from service account', async () => {
    const output = execSync(
      `node idTokenFromServiceAccount ${TARGET_AUDIENCE} ${keyFile}`
    );

    assert.match(output, /Generated ID token./);
  });

  it('should verify google id token', async () => {
    const jsonConfig = require(keyFile);
    const client = auth.fromJSON(jsonConfig);

    const idToken = await client.fetchIdToken(TARGET_AUDIENCE);

    const output = execSync(
      `node verifyGoogleIdToken ${idToken} ${TARGET_AUDIENCE} https://www.googleapis.com/oauth2/v3/certs`
    );

    assert.match(output, /ID token verified./);
  });
});
