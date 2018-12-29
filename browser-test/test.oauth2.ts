/**
 * Copyright 2018 Google Inc. All Rights Reserved.
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

import * as assert from 'assert';
import {AxiosError} from 'axios';
import * as fs from 'fs';
import * as sinon from 'sinon';
import * as path from 'path';
import * as qs from 'querystring';
import * as url from 'url';

import {GoogleAuth, OAuth2Client, DefaultTransporter} from '../src';

const CLIENT_ID = 'CLIENT_ID';
const CLIENT_SECRET = 'CLIENT_SECRET';
const REDIRECT_URI = 'REDIRECT';
const ACCESS_TYPE = 'offline';
const SCOPE = 'scopex';
const baseUrl = 'https://oauth2.googleapis.com';

class FakeTransporter {
  result: {};

  constructor(result: {}) {
    this.result = result;
  }

  // @ts-ignore type check for fake transporter
  async request() {
    return this.result;
  }
}

describe('Browser OAuth2 tests', () => {
  it('should generate a valid consent page url', done => {
    const opts = {
      access_type: ACCESS_TYPE,
      scope: SCOPE,
      response_type: 'code token'
    };

    const oauth2client = new OAuth2Client({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI
    });

    const generated = oauth2client.generateAuthUrl(opts);
    const parsed = url.parse(generated);
    if (typeof parsed.query !== 'string') {
      throw new Error('Unable to parse querystring');
    }
    const query = qs.parse(parsed.query);
    assert.strictEqual(query.response_type, 'code token');
    assert.strictEqual(query.access_type, ACCESS_TYPE);
    assert.strictEqual(query.scope, SCOPE);
    assert.strictEqual(query.client_id, CLIENT_ID);
    assert.strictEqual(query.redirect_uri, REDIRECT_URI);
    done();
  });

  it('getToken should work', async () => {
    const now = (new Date()).getTime();
    const oauth2client = new OAuth2Client({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI
    });
    // @ts-ignore fake transporter assignment
    const stub = sinon.stub(oauth2client.transporter, "request");
    // @ts-ignore TS2345
    stub.returns(Promise.resolve({access_token: 'abc', refresh_token: '123', expires_in: 10}));
//    oauth2client.transporter = new FakeTransporter({access_token: 'abc', refresh_token: '123', expires_in: 10});
    oauth2client.getToken('code here', (err, tokens) => {
      assert(tokens!.expiry_date! >= now + (10 * 1000));
      assert(tokens!.expiry_date! <= now + (15 * 1000));
    });
  });
});
