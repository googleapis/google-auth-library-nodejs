// Copyright 2017 Google LLC
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
import * as gal from '../src';

describe(__filename, () => {
  it('should publicly export GoogleAuth', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cjs = require('../src');
    assert.strictEqual(cjs.GoogleAuth, gal.GoogleAuth);
  });

  it('should publicly export DefaultTransporter', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cjs = require('../src');
    assert.strictEqual(cjs.DefaultTransporter, gal.DefaultTransporter);
  });

  it('should export all the things', () => {
    assert.ok(gal.CodeChallengeMethod);
    assert.ok(gal.Compute);
    assert.ok(gal.DefaultTransporter);
    assert.ok(gal.IAMAuth);
    assert.ok(gal.JWT);
    assert.ok(gal.JWTAccess);
    assert.ok(gal.OAuth2Client);
    assert.ok(gal.UserRefreshClient);
    assert.ok(gal.GoogleAuth);
  });
});
