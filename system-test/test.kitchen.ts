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
import {describe, it, afterEach} from 'mocha';
import * as execa from 'execa';
import * as fs from 'fs';
import * as mv from 'mv';
import {ncp} from 'ncp';
import * as os from 'os';
import * as path from 'path';
import {promisify} from 'util';

const mvp = promisify(mv) as {} as (...args: string[]) => Promise<void>;
const ncpp = promisify(ncp);
const keep = !!process.env.GALN_KEEP_TEMPDIRS;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json');

let stagingDir: string;
async function packAndInstall() {
  stagingDir = await fs.promises.mkdtemp(
    path.join(os.tmpdir(), 'google-auth-library-nodejs-pack-')
  );

  await execa('npm', ['pack'], {stdio: 'inherit'});
  const tarball = `${pkg.name}-${pkg.version}.tgz`;
  // stagingPath can be on another filesystem so fs.rename() will fail
  // with EXDEV, hence we use `mv` module here.
  await mvp(tarball, `${stagingDir}/google-auth-library.tgz`);
  await ncpp('system-test/fixtures/kitchen', `${stagingDir}/`);
  await execa('npm', ['install'], {cwd: `${stagingDir}/`, stdio: 'inherit'});
}

describe('pack and install', () => {
  /**
   * Create a staging directory with temp fixtures used to test on a fresh
   * application.
   */
  it('should be able to use the d.ts', async function () {
    // npm, once in a blue moon, fails during pack process. If this happens,
    // we should be safe to retry.
    this.retries(3);
    this.timeout(40000);
    await packAndInstall();
  });

  it('should be able to webpack the library', async function () {
    this.retries(3);
    this.timeout(40000);
    await packAndInstall();
    // we expect npm install is executed in the before hook
    await execa('npx', ['webpack'], {cwd: `${stagingDir}/`, stdio: 'inherit'});
    const bundle = path.join(stagingDir, 'dist', 'bundle.min.js');
    const stat = fs.statSync(bundle);
    assert(stat.size < 512 * 1024);
  });

  /**
   * CLEAN UP - remove the staging directory when done.
   */
  afterEach('cleanup staging', async () => {
    if (!keep) {
      if ('rm' in fs.promises) {
        await fs.promises.rm(stagingDir, {
          force: true,
          recursive: true,
        });
      } else {
        // Must be on Node 14-.
        // Here, `rmdir` can also delete files.
        // Background: https://github.com/nodejs/node/issues/34278
        await fs.promises.rmdir(stagingDir, {
          recursive: true,
        });
      }
    }
  });
});
