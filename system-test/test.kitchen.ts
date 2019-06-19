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

import * as assert from 'assert';
import * as execa from 'execa';
import * as fs from 'fs';
import * as mv from 'mv';
import {ncp} from 'ncp';
import * as path from 'path';
import * as tmp from 'tmp';
import {promisify} from 'util';

const mvp = (promisify(mv) as {}) as (...args: string[]) => Promise<void>;
const ncpp = promisify(ncp);
const keep = !!process.env.GALN_KEEP_TEMPDIRS;
const stagingDir = tmp.dirSync({keep, unsafeCleanup: true});
const stagingPath = stagingDir.name;
const pkg = require('../../package.json');

describe('pack and install', () => {
  /**
   * Create a staging directory with temp fixtures used to test on a fresh
   * application.
   */
  before('should be able to use the d.ts', async function() {
    this.timeout(40000);
    console.log(`${__filename} staging area: ${stagingPath}`);
    await execa('npm', ['pack'], {stdio: 'inherit'});
    const tarball = `${pkg.name}-${pkg.version}.tgz`;
    // stagingPath can be on another filesystem so fs.rename() will fail
    // with EXDEV, hence we use `mv` module here.
    await mvp(tarball, `${stagingPath}/google-auth-library.tgz`);
    await ncpp('system-test/fixtures/kitchen', `${stagingPath}/`);
    await execa('npm', ['install'], {cwd: `${stagingPath}/`, stdio: 'inherit'});
  });

  it('should be able to webpack the library', async () => {
    // we expect npm install is executed in the before hook
    await execa('npx', ['webpack'], {cwd: `${stagingPath}/`, stdio: 'inherit'});
    const bundle = path.join(stagingPath, 'dist', 'bundle.min.js');
    const stat = fs.statSync(bundle);
    assert(stat.size < 256 * 1024);
  }).timeout(20000);

  /**
   * CLEAN UP - remove the staging directory when done.
   */
  after('cleanup staging', () => {
    if (!keep) {
      stagingDir.removeCallback();
    }
  });
});
