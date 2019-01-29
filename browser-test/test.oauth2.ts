/**
 * Copyright 2019 Google LLC. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// <reference path='../node_modules/@types/sinon/ts3.1/index.d.ts'>

import * as base64js from 'base64-js';
import {assert} from 'chai';
import * as sinon from 'sinon';

// Not all browsers support `TextEncoder`. The following `require` will
// provide a fast UTF8-only replacement for those browsers that don't support
// text encoding natively.
require('fast-text-encoding');

import {CodeChallengeMethod, OAuth2Client} from '../src';
import {CertificateFormat} from '../src/auth/oauth2client';
import {JwkCertificate} from '../src/crypto/crypto';

const CLIENT_ID = 'CLIENT_ID';
const CLIENT_SECRET = 'CLIENT_SECRET';
const REDIRECT_URI = 'REDIRECT';
const ACCESS_TYPE = 'offline';
const SCOPE = 'scopex';
const FEDERATED_SIGNON_JWK_CERTS = [
  {
    'kid': '4665c2781899014617337df9cbf220686505a06c',
    'e': 'AQAB',
    'kty': 'RSA',
    'alg': 'RS256',
    'n':
        'o27xh_y7EEIoBXJuXzgfvFY80Cbk8Efn2b5ZFEwPIwFFBoNxvfbRt3wsZoMulMcZbU5uQ8q82FZBUmpwAlybQ0pBm79XDnL0kEDl1pJjyuaNE4JGOdBosvG5_SBaa7CCq9ukTeTLZgDR_YfcmP4-XQfhWuS-vx7hTz13GzmVgO8FyMH4EYm2ZyOY-otx35sM6toF__W1MiGcwty4Dp0qPHeZ3a34saNc_miQS5lzMcUgMYBKCQZ-P7pSeQhgVmwGYWr_93fqZEPQdOFC-Qwgrww1dZ7cv9INkjFkBKiWQLEiXJKoUSp2BwL2CqENYhuS04g5ZkDV7lVpOxOuHucEzQ',
    'use': 'sig'
  },
  {
    'use': 'sig',
    'kid': '7978a91347261a291bd71dcab4a464be7d279666',
    'e': 'AQAB',
    'kty': 'RSA',
    'alg': 'RS256',
    'n':
        'sFlU5LpHUtYIm7B27iiu7c4ZPZk7ULUNmFdMVsTmYJxJqQBKUIKU9ozwF6TlUsECmYUMLpQhX_iHuaZRcpG2YiG7jbmi9HMlonIXX7uUe7PIf8rNHhveX_VI7ZpwPTnab3_7ciy_o8ZFde6KNltkx_DLRO6hXf6z6ow1APFIIriaNlF8niz5cy0fPIv0e_Z2p13Sz3mnAACjBKZGPw2X9GWh5XpRoDEQBcibXpeLuA7ti8zLZuH-9ybXOoou699fr4QHFxUkcd_8fFqmzO5PKnlOnJZ0gtuXCCYYc9XPX-WSqlqbGNMZy0Giu2wHbNbeWdepkgVlGuJonTnMx4gLuQ'
  }
];
const FEDERATED_SIGNON_JWK_CERTS_AXIOS_RESPONSE = {
  'headers': {
    'cache-control':
        'cache-control: public, max-age=24000, must-revalidate, no-transform'
  },
  'data': {'keys': FEDERATED_SIGNON_JWK_CERTS}
};
// The following private and public keys were copied from JWK RFC 7517:
// https://tools.ietf.org/html/rfc7517
const privateKey = {
  'kty': 'RSA',
  'n':
      '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  'e': 'AQAB',
  'd':
      'X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q',
  'p':
      '83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs',
  'q':
      '3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk',
  'dp':
      'G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0',
  'dq':
      's9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk',
  'qi':
      'GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU',
  'alg': 'RS256',
  'kid': '2011-04-29'
};
const publicKey = {
  'kty': 'RSA',
  'n':
      '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  'e': 'AQAB',
  'alg': 'RS256',
  'kid': '2011-04-29'
};

describe('Browser OAuth2 tests', () => {
  let client: OAuth2Client;

  beforeEach(() => {
    client = new OAuth2Client({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI
    });
  });

  it('should generate a valid consent page url', () => {
    const opts = {
      access_type: ACCESS_TYPE,
      scope: SCOPE,
      response_type: 'code token'
    };

    const generated = client.generateAuthUrl(opts);
    const url = new URL(generated);
    const params = url.searchParams;
    assert.strictEqual(params.get('response_type'), 'code token');
    assert.strictEqual(params.get('access_type'), ACCESS_TYPE);
    assert.strictEqual(params.get('scope'), SCOPE);
    assert.strictEqual(params.get('client_id'), CLIENT_ID);
    assert.strictEqual(params.get('redirect_uri'), REDIRECT_URI);
  });

  it('getToken should work', async () => {
    const now = Date.now();
    const stub = sinon.stub().resolves(
        {data: {access_token: 'abc', refresh_token: '123', expires_in: 10}});
    client.transporter.request = stub;
    const response = await client.getToken('code here');
    const tokens = response.tokens;
    assert.isAbove(tokens!.expiry_date!, now + (10 * 1000));
    assert.isBelow(tokens!.expiry_date!, now + (15 * 1000));
  });

  it('getFederatedSignonCerts talks to correct endpoint', async () => {
    const stub =
        sinon.stub().resolves(FEDERATED_SIGNON_JWK_CERTS_AXIOS_RESPONSE);
    client.transporter.request = stub;
    const result = await client.getFederatedSignonCertsAsync();
    const expectedCerts: {[kid: string]: JwkCertificate} = {};
    for (const cert of FEDERATED_SIGNON_JWK_CERTS) {
      expectedCerts[cert.kid] = cert;
    }
    assert.strictEqual(result.format, CertificateFormat.JWK);
    assert.deepStrictEqual(result.certs, expectedCerts);
  });

  it('getFederatedSignonCerts caches certificates', async () => {
    const stub =
        sinon.stub().resolves(FEDERATED_SIGNON_JWK_CERTS_AXIOS_RESPONSE);
    client.transporter.request = stub;
    const result1 = await client.getFederatedSignonCertsAsync();
    const result2 = await client.getFederatedSignonCertsAsync();
    assert(stub.calledOnce);
    assert.deepStrictEqual(result1.certs, result2.certs);
    assert.deepStrictEqual(result1.format, result2.format);
  });

  it('should generate a valid code verifier and resulting challenge',
     async () => {
       const codes = await client.generateCodeVerifierAsync();
       assert.match(codes.codeVerifier, /^[a-zA-Z0-9\-\.~_]{128}$/);
     });

  it('should include code challenge and method in the url', async () => {
    const codes = await client.generateCodeVerifierAsync();
    const authUrl = client.generateAuthUrl({
      code_challenge: codes.codeChallenge,
      code_challenge_method: CodeChallengeMethod.S256
    });
    const url = new URL(authUrl);
    const params = url.searchParams;
    assert.strictEqual(params.get('code_challenge'), codes.codeChallenge);
    assert.strictEqual(
        params.get('code_challenge_method'), CodeChallengeMethod.S256);
  });

  it('should verify a valid certificate against a jwt', async () => {
    const maxLifetimeSecs = 86400;
    const now = Date.now() / 1000;
    const expiry = now + (maxLifetimeSecs / 2);
    const idToken = '{' +
        '"iss":"testissuer",' +
        '"aud":"testaudience",' +
        '"azp":"testauthorisedparty",' +
        '"email_verified":"true",' +
        '"id":"123456789",' +
        '"sub":"123456789",' +
        '"email":"test@test.com",' +
        '"iat":' + now + ',' +
        '"exp":' + expiry + '}';
    const envelope = JSON.stringify({kid: 'keyid', alg: 'RS256'});
    let data = base64js.fromByteArray(new TextEncoder().encode(envelope)) +
        '.' + base64js.fromByteArray(new TextEncoder().encode(idToken));
    const algo = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {name: 'SHA-256'},
    };
    const cryptoKey = await window.crypto.subtle.importKey(
        'jwk', privateKey, algo, true, ['sign']);
    const signature = await window.crypto.subtle.sign(
        algo, cryptoKey, new TextEncoder().encode(data));
    data += '.' + base64js.fromByteArray(new Uint8Array(signature));
    const login = await client.verifySignedJwtWithCertsAsync(
        data, {keyid: publicKey}, 'testaudience');
    assert.strictEqual(login.getUserId(), '123456789');
  });
});
