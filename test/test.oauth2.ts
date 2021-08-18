// Copyright 2019 Google LLC
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

import * as assert from 'assert';
import {describe, it, beforeEach, afterEach} from 'mocha';
import * as crypto from 'crypto';
import * as formatEcdsa from 'ecdsa-sig-formatter';
import * as fs from 'fs';
import {GaxiosError} from 'gaxios';
import * as nock from 'nock';
import * as path from 'path';
import * as qs from 'querystring';
import * as sinon from 'sinon';

import {CodeChallengeMethod, OAuth2Client} from '../src';
import {LoginTicket} from '../src/auth/loginticket';
import {DownscopedAccessTokenResponse} from '../src/auth/oauth2client';

nock.disableNetConnect();

describe('oauth2', () => {
  const CLIENT_ID = 'CLIENT_ID';
  const CLIENT_SECRET = 'CLIENT_SECRET';
  const REDIRECT_URI = 'REDIRECT';
  const ACCESS_TYPE = 'offline';
  const SCOPE = 'scopex';
  const SCOPE_ARRAY = ['scopex', 'scopey'];
  const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
  const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');
  const baseUrl = 'https://oauth2.googleapis.com';
  const certsPath = '/oauth2/v1/certs';
  const certsResPath = path.join(
    __dirname,
    '../../test/fixtures/oauthcertspem.json'
  );
  const publicKeyEcdsa = fs.readFileSync(
    './test/fixtures/fake-ecdsa-public.pem',
    'utf-8'
  );
  const privateKeyEcdsa = fs.readFileSync(
    './test/fixtures/fake-ecdsa-private.pem',
    'utf-8'
  );
  const pubkeysResPath = path.join(
    __dirname,
    '../../test/fixtures/ecdsapublickeys.json'
  );

  describe(__filename, () => {
    let client: OAuth2Client;
    let sandbox: sinon.SinonSandbox;
    beforeEach(() => {
      client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
      sandbox = sinon.createSandbox();
    });

    afterEach(() => {
      nock.cleanAll();
      sandbox.restore();
    });

    it('should generate a valid consent page url', done => {
      const opts = {
        access_type: ACCESS_TYPE,
        scope: SCOPE,
        response_type: 'code token',
      };

      const oauth2client = new OAuth2Client({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
      });

      const generated = oauth2client.generateAuthUrl(opts);
      const query = new URL(generated).searchParams;
      assert.strictEqual(query.get('response_type'), 'code token');
      assert.strictEqual(query.get('access_type'), ACCESS_TYPE);
      assert.strictEqual(query.get('scope'), SCOPE);
      assert.strictEqual(query.get('client_id'), CLIENT_ID);
      assert.strictEqual(query.get('redirect_uri'), REDIRECT_URI);
      done();
    });

    it('should throw an error if generateAuthUrl is called with invalid parameters', () => {
      const opts = {
        access_type: ACCESS_TYPE,
        scope: SCOPE,
        code_challenge_method: CodeChallengeMethod.S256,
      };
      assert.throws(
        () => client.generateAuthUrl(opts),
        /If a code_challenge_method is provided, code_challenge must be included/
      );
    });

    it('should generate a valid code verifier and resulting challenge', async () => {
      const codes = await client.generateCodeVerifierAsync();
      // ensure the code_verifier matches all requirements
      assert.strictEqual(codes.codeVerifier.length, 128);
      const match = codes.codeVerifier.match(/[a-zA-Z0-9-.~_]*/);
      assert(match);
      if (!match) return;
      assert(match.length > 0 && match[0] === codes.codeVerifier);
    });

    it('should include code challenge and method in the url', async () => {
      const codes = await client.generateCodeVerifierAsync();
      const authUrl = client.generateAuthUrl({
        code_challenge: codes.codeChallenge,
        code_challenge_method: CodeChallengeMethod.S256,
      });
      const props = new URL(authUrl).searchParams;
      assert.strictEqual(props.get('code_challenge'), codes.codeChallenge);
      assert.strictEqual(
        props.get('code_challenge_method'),
        CodeChallengeMethod.S256
      );
    });

    it('should verifyIdToken properly', async () => {
      const fakeCerts = {a: 'a', b: 'b'};
      const idToken = 'idToken';
      const audience = 'fakeAudience';
      const maxExpiry = 5;
      const payload = {
        aud: 'aud',
        sub: 'sub',
        iss: 'iss',
        iat: 1514162443,
        exp: 1514166043,
      };
      const scope = nock('https://www.googleapis.com')
        .get('/oauth2/v1/certs')
        .reply(200, fakeCerts);
      client.verifySignedJwtWithCertsAsync = async (
        jwt: string,
        certs: {},
        requiredAudience: string | string[],
        issuers?: string[],
        theMaxExpiry?: number
      ) => {
        assert.strictEqual(jwt, idToken);
        assert.deepStrictEqual(certs, fakeCerts);
        assert.strictEqual(requiredAudience, audience);
        assert.strictEqual(theMaxExpiry, maxExpiry);
        return new LoginTicket('c', payload);
      };
      const result = await client.verifyIdToken({idToken, audience, maxExpiry});
      scope.done();
      assert.notStrictEqual(result, null);
      if (result) {
        assert.strictEqual(result.getEnvelope(), 'c');
        assert.strictEqual(result.getPayload(), payload);
      }
    });

    it('should provide a reasonable error in verifyIdToken with wrong parameters', async () => {
      const fakeCerts = {a: 'a', b: 'b'};
      const idToken = 'idToken';
      const audience = 'fakeAudience';
      const payload = {
        aud: 'aud',
        sub: 'sub',
        iss: 'iss',
        iat: 1514162443,
        exp: 1514166043,
      };
      client.verifySignedJwtWithCertsAsync = async (
        jwt: string,
        certs: {},
        requiredAudience: string
      ) => {
        assert.strictEqual(jwt, idToken);
        assert.deepStrictEqual(certs, fakeCerts);
        assert.strictEqual(requiredAudience, audience);
        return new LoginTicket('c', payload);
      };
      assert.throws(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        () => (client as any).verifyIdToken(idToken, audience),
        /This method accepts an options object as the first parameter, which includes the idToken, audience, and maxExpiry./
      );
    });

    it('should allow scopes to be specified as array', () => {
      const opts = {
        access_type: ACCESS_TYPE,
        scope: SCOPE_ARRAY,
        response_type: 'code token',
      };
      const generated = client.generateAuthUrl(opts);
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('scope'), SCOPE_ARRAY.join(' '));
    });

    it('should set response_type param to code if none is given while generating the consent page url', () => {
      const generated = client.generateAuthUrl();
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('response_type'), 'code');
    });

    it('should verify a valid certificate against a jwt', async () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = JSON.stringify({kid: 'keyid', alg: 'RS256'});
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      const login = await client.verifySignedJwtWithCertsAsync(
        data,
        {keyid: publicKey},
        'testaudience'
      );
      assert.strictEqual(login.getUserId(), '123456789');
    });

    it('should fail due to invalid audience', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"wrongaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Wrong recipient/
      );
    });

    it('should fail due to invalid array of audiences', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"wrongaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      const validAudiences = ['testaudience', 'extra-audience'];
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          validAudiences
        ),
        /Wrong recipient/
      );
    });

    it('should fail due to invalid signature', () => {
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":1393241597,' +
        '"exp":1393245497' +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      // Originally: data += '.'+signature;
      data += signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Wrong number of segments/
      );
    });

    it('should fail due to invalid envelope', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid"' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Can't parse token envelope/
      );
    });

    it('should fail due to invalid payload', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer"' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Can't parse token payload/
      );
    });

    it('should fail due to invalid signature', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      const data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64') +
        '.' +
        'broken-signature';
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Invalid token signature/
      );
    });

    it('should fail due to no expiration date', () => {
      const now = new Date().getTime() / 1000;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /No expiration time/
      );
    });

    it('should fail due to no issue time', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /No issue time/
      );
    });

    it('should fail due to certificate with expiration date in future', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + 2 * maxLifetimeSecs;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Expiration time too far in future/
      );
    });

    it('should pass due to expiration date in future with adjusted max expiry', async () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + 2 * maxLifetimeSecs;
      const maxExpiry = 3 * maxLifetimeSecs;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      await client.verifySignedJwtWithCertsAsync(
        data,
        {keyid: publicKey},
        'testaudience',
        ['testissuer'],
        maxExpiry
      );
    });

    it('should fail due to token being used to early', () => {
      const maxLifetimeSecs = 86400;
      const clockSkews = 300;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const issueTime = now + clockSkews * 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        issueTime +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Token used too early/
      );
    });

    it('should fail due to token being used to late', () => {
      const maxLifetimeSecs = 86400;
      const clockSkews = 300;
      const now = new Date().getTime() / 1000;
      const expiry = now - maxLifetimeSecs / 2;
      const issueTime = now - clockSkews * 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        issueTime +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';

      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience'
        ),
        /Token used too late/
      );
    });

    it('should fail due to invalid issuer', () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"invalidissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      return assert.rejects(
        client.verifySignedJwtWithCertsAsync(
          data,
          {keyid: publicKey},
          'testaudience',
          ['testissuer']
        ),
        /Invalid issuer/
      );
    });

    it('should pass due to valid issuer', async () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"RS256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('sha256');
      signer.update(data);
      const signature = signer.sign(privateKey, 'base64');
      data += '.' + signature;
      await client.verifySignedJwtWithCertsAsync(
        data,
        {keyid: publicKey},
        'testaudience',
        ['testissuer']
      );
    });

    it('should pass for ECDSA-encrypted JWTs', async () => {
      const maxLifetimeSecs = 86400;
      const now = new Date().getTime() / 1000;
      const expiry = now + maxLifetimeSecs / 2;
      const idToken =
        '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' +
        now +
        ',' +
        '"exp":' +
        expiry +
        '}';
      const envelope = '{' + '"kid":"keyid",' + '"alg":"ES256"' + '}';
      let data =
        Buffer.from(envelope).toString('base64') +
        '.' +
        Buffer.from(idToken).toString('base64');
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(data);
      const signature = formatEcdsa.derToJose(
        signer.sign(privateKeyEcdsa, 'base64'),
        'ES256'
      );
      data += '.' + signature;
      await client.verifySignedJwtWithCertsAsync(
        data,
        {keyid: publicKeyEcdsa},
        'testaudience',
        ['testissuer']
      );
    });

    it('should be able to retrieve a list of Google certificates', done => {
      const scope = nock('https://www.googleapis.com')
        .get(certsPath)
        .replyWithFile(200, certsResPath);
      client.getFederatedSignonCerts((err, certs) => {
        assert.strictEqual(err, null);
        assert.strictEqual(Object.keys(certs!).length, 2);
        assert.notStrictEqual(
          certs!.a15eea964ab9cce480e5ef4f47cb17b9fa7d0b21,
          null
        );
        assert.notStrictEqual(
          certs!['39596dc3a3f12aa74b481579e4ec944f86d24b95'],
          null
        );
        scope.done();
        done();
      });
    });

    it('should be able to retrieve a list of Google certificates from cache again', done => {
      const scope = nock('https://www.googleapis.com')
        .defaultReplyHeaders({
          'Cache-Control':
            'public, max-age=23641, must-revalidate, no-transform',
          'Content-Type': 'application/json',
        })
        .get(certsPath)
        .replyWithFile(200, certsResPath);
      client.getFederatedSignonCerts((err, certs) => {
        assert.strictEqual(err, null);
        assert.strictEqual(Object.keys(certs!).length, 2);
        scope.done(); // has retrieved from nock... nock no longer will reply
        client.getFederatedSignonCerts((err2, certs2) => {
          assert.strictEqual(err2, null);
          assert.strictEqual(Object.keys(certs2!).length, 2);
          scope.done();
          done();
        });
      });
    });

    it('should be able to retrieve a list of IAP certificates', done => {
      const scope = nock('https://www.gstatic.com')
        .get('/iap/verify/public_key')
        .replyWithFile(200, pubkeysResPath);
      client.getIapPublicKeys((err, pubkeys) => {
        assert.strictEqual(err, null);
        assert.strictEqual(Object.keys(pubkeys!).length, 2);
        assert.notStrictEqual(pubkeys!.f9R3yg, null);
        assert.notStrictEqual(pubkeys!['2nMJtw'], null);
        scope.done();
        done();
      });
    });

    it('should set redirect_uri if not provided in options', () => {
      const generated = client.generateAuthUrl({});
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('redirect_uri'), REDIRECT_URI);
    });

    it('should set client_id if not provided in options', () => {
      const generated = client.generateAuthUrl({});
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('client_id'), CLIENT_ID);
    });

    it('should override redirect_uri if provided in options', () => {
      const generated = client.generateAuthUrl({redirect_uri: 'overridden'});
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('redirect_uri'), 'overridden');
    });

    it('should override client_id if provided in options', () => {
      const generated = client.generateAuthUrl({client_id: 'client_override'});
      const parsed = new URL(generated).searchParams;
      assert.strictEqual(parsed.get('client_id'), 'client_override');
    });

    it('should return error in callback on request', done => {
      client.request({}, (err, result) => {
        assert.strictEqual(
          err!.message,
          'No access, refresh token or API key is set.'
        );
        assert.strictEqual(result, undefined);
        done();
      });
    });

    it('should not emit warning on refreshAccessToken', async () => {
      let warned = false;
      sandbox.stub(process, 'emitWarning').callsFake(() => (warned = true));
      client.refreshAccessToken(() => {
        assert.strictEqual(warned, false);
      });
    });

    it('should return error in callback on refreshAccessToken', done => {
      client.refreshAccessToken((err, result) => {
        assert.strictEqual(err!.message, 'No refresh token is set.');
        assert.strictEqual(result, undefined);
        done();
      });
    });

    function mockExample() {
      return [
        nock(baseUrl)
          .post('/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'},
          })
          .reply(200, {access_token: 'abc123', expires_in: 1}),
        nock('http://example.com').get('/').reply(200),
      ];
    }

    it('should refresh token if missing access token', done => {
      const scopes = mockExample();
      const accessToken = 'abc123';
      let raisedEvent = false;
      const refreshToken = 'refresh-token-placeholder';
      client.credentials = {refresh_token: refreshToken};

      // ensure the tokens event is raised
      client.on('tokens', tokens => {
        assert.strictEqual(tokens.access_token, accessToken);
        raisedEvent = true;
      });

      client.request({url: 'http://example.com'}, () => {
        scopes.forEach(s => s.done());
        assert(raisedEvent);
        assert.strictEqual(accessToken, client.credentials.access_token);
        done();
      });
    });

    it('should unify the promise when refreshing the token', async () => {
      // Mock a single call to the token server, and 3 calls to the example
      // endpoint. This makes sure that refreshToken is called only once.
      const scopes = [
        nock(baseUrl)
          .post('/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'},
          })
          .reply(200, {access_token: 'abc123', expires_in: 1}),
        nock('http://example.com').get('/').thrice().reply(200),
      ];
      client.credentials = {refresh_token: 'refresh-token-placeholder'};
      await Promise.all([
        client.request({url: 'http://example.com'}),
        client.request({url: 'http://example.com'}),
        client.request({url: 'http://example.com'}),
      ]);
      scopes.forEach(s => s.done());
      assert.strictEqual('abc123', client.credentials.access_token);
    });

    it('should clear the cached refresh token promise after completion', async () => {
      // Mock 2 calls to the token server and 2 calls to the example endpoint.
      // This makes sure that the token endpoint is invoked twice, preventing
      // the promise from getting cached for too long.
      const scopes = [
        nock(baseUrl)
          .post('/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'},
          })
          .twice()
          .reply(200, {access_token: 'abc123', expires_in: 100000}),
        nock('http://example.com').get('/').twice().reply(200),
      ];
      client.credentials = {refresh_token: 'refresh-token-placeholder'};
      await client.request({url: 'http://example.com'});
      client.credentials.access_token = null;
      await client.request({url: 'http://example.com'});
      scopes.forEach(s => s.done());
      assert.strictEqual('abc123', client.credentials.access_token);
    });

    it('should clear the cached refresh token promise after throw', async () => {
      // Mock a failed call to the refreshToken endpoint. This should trigger
      // a second call to refreshToken, which should use a different promise.
      const scopes = [
        nock(baseUrl)
          .post('/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'},
          })
          .reply(500)
          .post('/token', undefined, {
            reqheaders: {'content-type': 'application/x-www-form-urlencoded'},
          })
          .reply(200, {access_token: 'abc123', expires_in: 100000}),
        nock('http://example.com').get('/').reply(200),
      ];
      client.credentials = {refresh_token: 'refresh-token-placeholder'};
      try {
        await client.request({url: 'http://example.com'});
        // eslint-disable-next-line no-empty
      } catch (e) {}
      await client.request({url: 'http://example.com'});
      scopes.forEach(s => s.done());
      assert.strictEqual('abc123', client.credentials.access_token);
    });

    it('should refresh if access token is expired', done => {
      client.setCredentials({
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: new Date().getTime() - 1000,
      });
      const scopes = mockExample();
      client.request({url: 'http://example.com'}, () => {
        scopes.forEach(s => s.done());
        assert.strictEqual('abc123', client.credentials.access_token);
        done();
      });
    });

    it('should refresh if access token will expired soon and time to refresh before expiration is set', async () => {
      const client = new OAuth2Client({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        eagerRefreshThresholdMillis: 5000,
      });
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: new Date().getTime() + 3000,
      };
      const scopes = mockExample();
      await client.request({url: 'http://example.com'});
      assert.strictEqual('abc123', client.credentials.access_token);
      scopes.forEach(s => s.done());
    });

    it('should not refresh if access token will not expire soon and time to refresh before expiration is set', async () => {
      const client = new OAuth2Client({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        eagerRefreshThresholdMillis: 5000,
      });
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: new Date().getTime() + 10000,
      };
      const scopes = mockExample();
      await client.request({url: 'http://example.com'});
      assert.strictEqual(
        'initial-access-token',
        client.credentials.access_token
      );
      assert.strictEqual(false as boolean, scopes[0].isDone());
      scopes[1].done();
    });

    it('should not refresh if not expired', done => {
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: new Date().getTime() + 500000,
      };
      const scopes = mockExample();
      client.request({url: 'http://example.com'}, () => {
        assert.strictEqual(
          'initial-access-token',
          client.credentials.access_token
        );
        assert.strictEqual(false as boolean, scopes[0].isDone());
        scopes[1].done();
        done();
      });
    });

    it('should assume access token is not expired', done => {
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
      };
      const scopes = mockExample();
      client.request({url: 'http://example.com'}, () => {
        assert.strictEqual(
          'initial-access-token',
          client.credentials.access_token
        );
        assert.strictEqual(false as boolean, scopes[0].isDone());
        scopes[1].done();
        done();
      });
    });

    [401, 403].forEach(code => {
      it(`should refresh token if the server returns ${code}`, done => {
        const scope = nock('http://example.com')
          .get('/access')
          .reply(code, {
            error: {code, message: 'Invalid Credentials'},
          });
        const scopes = mockExample();
        client.credentials = {
          access_token: 'initial-access-token',
          refresh_token: 'refresh-token-placeholder',
        };
        client.request({url: 'http://example.com/access'}, () => {
          scope.done();
          scopes[0].done();
          assert.strictEqual('abc123', client.credentials.access_token);
          done();
        });
      });

      it(`should refresh token if the server returns ${code} with forceRefreshOnFailure`, done => {
        const client = new OAuth2Client({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          redirectUri: REDIRECT_URI,
          forceRefreshOnFailure: true,
        });
        const scope = nock('http://example.com')
          .get('/access')
          .reply(code, {
            error: {code, message: 'Invalid Credentials'},
          });
        const scopes = mockExample();
        client.credentials = {
          access_token: 'initial-access-token',
          refresh_token: 'refresh-token-placeholder',
          expiry_date: new Date().getTime() + 500000,
        };
        client.request({url: 'http://example.com/access'}, () => {
          scope.done();
          scopes[0].done();
          assert.strictEqual('abc123', client.credentials.access_token);
          done();
        });
      });

      it('should call refreshHandler and set credential if token expires in request()', async () => {
        const scope = nock('http://example.com')
          .get('/access')
          .reply(code, {
            error: {code, message: 'Invalid Credentials'},
          });
        const expectedDownscopedCred = {
          access_token: 'access_token',
          expiry_date: 123456789,
        };
        client.refreshHandler = async () => {
          return expectedDownscopedCred;
        };
        client.setCredentials({
          access_token: 'initial-access-token',
          expiry_date: new Date().getTime() - 1000,
        });
        await client.request({url: 'http://example.com'}, () => {
          scope.done();
          assert.strictEqual(
            client.credentials.access_token,
            expectedDownscopedCred.access_token
          );
          assert.strictEqual(
            client.credentials.expiry_date,
            expectedDownscopedCred.expiry_date
          );
        });
      });
    });

    it('should not retry requests with streaming data', done => {
      const s = fs.createReadStream('./test/fixtures/public.pem');
      const scope = nock('http://example.com').post('/').reply(401);
      client.credentials = {
        access_token: 'initial-access-token',
        refresh_token: 'refresh-token-placeholder',
        expiry_date: new Date().getTime() + 500000,
      };
      client.request(
        {method: 'POST', url: 'http://example.com', data: s},
        err => {
          scope.done();
          const e = err as GaxiosError;
          assert(e);
          assert.strictEqual(e.response!.status, 401);
          done();
        }
      );
    });

    it('should revoke credentials if access token present', done => {
      const scope = nock('https://oauth2.googleapis.com')
        .post('/revoke?token=abc')
        .reply(200, {success: true});
      client.credentials = {access_token: 'abc', refresh_token: 'abc'};
      client.revokeCredentials((err, result) => {
        assert.strictEqual(err, null);
        assert.strictEqual(result!.data!.success, true);
        assert.deepStrictEqual(client.credentials, {});
        scope.done();
        done();
      });
    });

    it('should clear credentials and return error if no access token to revoke', done => {
      client.credentials = {refresh_token: 'abc'};
      client.revokeCredentials((err, result) => {
        assert.strictEqual(err!.message, 'No access token to revoke.');
        assert.strictEqual(result, undefined);
        assert.deepStrictEqual(client.credentials, {});
        done();
      });
    });

    it('getToken should allow a code_verifier to be passed', async () => {
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      const res = await client.getToken({
        code: 'code here',
        codeVerifier: 'its_verified',
      });
      scope.done();
      assert(res.res);
      if (!res.res) return;
      const params = qs.parse(res.res.config.data);
      assert.strictEqual(params.code_verifier, 'its_verified');
    });

    it('getToken should set redirect_uri if not provided in options', async () => {
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      const res = await client.getToken({code: 'code here'});
      scope.done();
      assert(res.res);
      if (!res.res) return;
      const params = qs.parse(res.res.config.data);
      assert.strictEqual(params.redirect_uri, REDIRECT_URI);
    });

    it('getToken should set client_id if not provided in options', async () => {
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      const res = await client.getToken({code: 'code here'});
      scope.done();
      assert(res.res);
      if (!res.res) return;
      const params = qs.parse(res.res.config.data);
      assert.strictEqual(params.client_id, CLIENT_ID);
    });

    it('getToken should override redirect_uri if provided in options', async () => {
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      const res = await client.getToken({
        code: 'code here',
        redirect_uri: 'overridden',
      });
      scope.done();
      assert(res.res);
      if (!res.res) return;
      const params = qs.parse(res.res.config.data);
      assert.strictEqual(params.redirect_uri, 'overridden');
    });

    it('getToken should override client_id if provided in options', async () => {
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      const res = await client.getToken({
        code: 'code here',
        client_id: 'overridden',
      });
      scope.done();
      assert(res.res);
      if (!res.res) return;
      const params = qs.parse(res.res.config.data);
      assert.strictEqual(params.client_id, 'overridden');
    });

    it('should return expiry_date', done => {
      const now = new Date().getTime();
      const scope = nock(baseUrl)
        .post('/token', undefined, {
          reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'},
        })
        .reply(200, {
          access_token: 'abc',
          refresh_token: '123',
          expires_in: 10,
        });
      client.getToken('code here', (err, tokens) => {
        assert(tokens!.expiry_date! >= now + 10 * 1000);
        assert(tokens!.expiry_date! <= now + 15 * 1000);
        scope.done();
        done();
      });
    });

    it('should obtain token info', async () => {
      const accessToken = 'abc';
      const tokenInfo = {
        aud: 'naudience',
        user_id: '12345',
        scope: 'scope1 scope2',
        expires_in: 1234,
      };

      const scope = nock(baseUrl, {
        reqheaders: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Bearer ${accessToken}`,
        },
      })
        .post('/tokeninfo', () => true)
        .reply(200, tokenInfo);

      const info = await client.getTokenInfo(accessToken);
      scope.done();
      assert.strictEqual(info.aud, tokenInfo.aud);
      assert.strictEqual(info.user_id, tokenInfo.user_id);
      assert.deepStrictEqual(info.scopes, tokenInfo.scope.split(' '));
    });

    it('should refresh request header when refreshHandler is available', async () => {
      const expectedDownscopedCred = {
        access_token: 'access_token',
        expiry_date: 123456789,
      };
      client.refreshHandler = async () => {
        return expectedDownscopedCred;
      };
      client.setCredentials({
        access_token: 'initial-access-token',
        expiry_date: new Date().getTime() - 1000,
      });
      const expectedMetadata = {
        Authorization: 'Bearer access_token',
      };
      const requestMetaData = await client.getRequestHeaders(
        'http://example.com'
      );
      assert.deepStrictEqual(requestMetaData, expectedMetadata);
    });

    it('should throw if tries to refresh but no refresh token is available', async () => {
      client.setCredentials({
        access_token: 'initial-access-token',
        expiry_date: new Date().getTime() - 1000,
      });
      await assert.rejects(
        client.getRequestHeaders('http://example.com'),
        /No refresh token is set./
      );
    });

    it('should call refreshHandler and set credential if providing refresh handler callback', async () => {
      const expectedDownscopedCred = {
        access_token: 'access_token',
        expiry_date: 123456789,
      };
      client.refreshHandler = async () => {
        return expectedDownscopedCred;
      };
      const downscopedCred =
        (await client.refreshHandler()) as DownscopedAccessTokenResponse;
      assert.strictEqual(
        downscopedCred.access_token,
        expectedDownscopedCred.access_token
      );
      assert.strictEqual(
        downscopedCred.expiry_date,
        expectedDownscopedCred.expiry_date
      );
    });

    it('should refresh credential when refreshHandler is available in getAccessToken()', async () => {
      const expectedDownscopedCred = {
        access_token: 'access_token',
        expiry_date: 123456789,
      };
      client.refreshHandler = async () => {
        return expectedDownscopedCred;
      };
      client.setCredentials({
        access_token: 'initial-access-token',
        expiry_date: new Date().getTime() - 1000,
      });
      const downscopedCred = await client.getAccessToken();
      assert.strictEqual(
        downscopedCred.token,
        expectedDownscopedCred.access_token
      );
    });
  });
});
