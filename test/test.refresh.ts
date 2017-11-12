/**
 * Copyright 2013 Google Inc. All Rights Reserved.
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
import * as fs from 'fs';
import * as nock from 'nock';

import {GoogleAuth} from '../src/auth/googleauth';

nock.disableNetConnect();

// Creates a standard JSON credentials object for testing.
function createJSON() {
  return {
    client_secret: 'privatekey',
    client_id: 'client123',
    refresh_token: 'refreshtoken',
    type: 'authorized_user'
  };
}

describe('.fromJson', () => {

  it('should error on null json', (done) => {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (refresh as any).fromJSON(null, (err: Error) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on empty json', (done) => {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    refresh.fromJSON(({} as any), (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_id', (done) => {
    const json = createJSON();
    delete json.client_id;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing client_secret', (done) => {
    const json = createJSON();
    delete json.client_secret;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should error on missing refresh_token', (done) => {
    const json = createJSON();
    delete json.refresh_token;

    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should create UserRefreshClient with clientId_', (done) => {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.ifError(err);
      assert.equal(json.client_id, refresh._clientId);
      done();
    });
  });

  it('should create UserRefreshClient with clientSecret_', (done) => {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.ifError(err);
      assert.equal(json.client_secret, refresh._clientSecret);
      done();
    });
  });

  it('should create UserRefreshClient with _refreshToken', (done) => {
    const json = createJSON();
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromJSON(json, (err) => {
      assert.ifError(err);
      assert.equal(json.refresh_token, refresh._refreshToken);
      done();
    });
  });
});

describe('.fromStream', () => {

  it('should error on null stream', (done) => {
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    // Test verifies invalid parameter tests, which requires cast to any.
    // tslint:disable-next-line no-any
    (refresh as any).fromStream(null, (err: Error) => {
      assert.equal(true, err instanceof Error);
      done();
    });
  });

  it('should read the stream and create a UserRefreshClient', (done) => {
    // Read the contents of the file into a json object.
    const fileContents =
        fs.readFileSync('./test/fixtures/refresh.json', 'utf-8');
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./test/fixtures/refresh.json');

    // And pass it into the fromStream method.
    const auth = new GoogleAuth();
    const refresh = new auth.UserRefreshClient();
    refresh.fromStream(stream, (err) => {
      assert.ifError(err);

      // Ensure that the correct bits were pulled from the stream.
      assert.equal(json.client_id, refresh._clientId);
      assert.equal(json.client_secret, refresh._clientSecret);
      assert.equal(json.refresh_token, refresh._refreshToken);

      done();
    });
  });
});
