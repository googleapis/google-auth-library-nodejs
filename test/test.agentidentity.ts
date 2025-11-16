// Copyright 2025 Google LLC
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
import {describe, it, afterEach, beforeEach} from 'mocha';
import * as sinon from 'sinon';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import * as os from 'os';
import {getBindCertificateFingerprint} from '../src/auth/agentidentity';
import {TestUtils} from './utils';

const NON_AGENTIC_CERT_PATH = path.join(
  __dirname,
  '../../test/fixtures/external-account-cert/leaf.crt',
);

const AGENTIC_CERT_PATH = path.join(
  __dirname,
  '../../test/fixtures/external-account-cert/agentic_cert.pem',
);
const AGENTIC_CERT_PEM = fs.readFileSync(AGENTIC_CERT_PATH, 'utf-8');

describe('agentidentity', () => {
  let sandbox: sinon.SinonSandbox;
  let clock: sinon.SinonFakeTimers;
  let tmpDir: string;
  let configPath: string;
  let certPath: string;

  beforeEach(async () => {
    sandbox = sinon.createSandbox();
    clock = TestUtils.useFakeTimers(sandbox);
    tmpDir = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), 'agent-id-test-'),
    );
    configPath = path.join(tmpDir, 'config.json');
    certPath = path.join(tmpDir, 'cert.pem');
    delete process.env.GOOGLE_API_CERTIFICATE_CONFIG;
    delete process.env.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES;
  });

  afterEach(async () => {
    if (clock) {
      clock.restore();
    }
    sandbox.restore();
    await fs.promises.rm(tmpDir, {recursive: true, force: true});
  });

  it('should return undefined if CERTIFICATE_CONFIG env var is not set', async () => {
    const fingerprint = await getBindCertificateFingerprint();
    assert.strictEqual(fingerprint, undefined);
  });

  it('should return undefined if opted out via env var', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;
    process.env.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES =
      'false';
    const fingerprint = await getBindCertificateFingerprint();
    assert.strictEqual(fingerprint, undefined);
  });

  it('should fail if config file does not appear within timeout', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;

    const promise = getBindCertificateFingerprint();
    // Advance clock past the 30s timeout (50 * 100ms + 50 * 500ms = 30s)
    // Use tickAsync to ensure promises have a chance to resolve between ticks
    await clock.tickAsync(31000);

    await assert.rejects(
      promise,
      /Certificate config or certificate file not found after multiple retries/,
    );
  });

  it('should fail if cert file does not appear within timeout', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;

    // 1. Stub fs.existsSync
    // We simulate that the config file exists, but the cert file (certPath) NEVER exists.
    const existsStub = sandbox.stub(fs, 'existsSync');
    existsStub.withArgs(configPath).returns(true);
    existsStub.withArgs(certPath).returns(false);
    existsStub.callThrough(); // Allow other unrelated checks to pass

    // 2. Stub fs.promises.readFile
    // Return the config JSON immediately without hitting the disk.
    const readFileStub = sandbox.stub(fs.promises, 'readFile');
    readFileStub.withArgs(configPath, 'utf-8').resolves(
      JSON.stringify({
        cert_configs: {
          workload: {
            cert_path: certPath,
          },
        },
      }),
    );
    readFileStub.callThrough();

    // 3. Start the function
    const promise = getBindCertificateFingerprint();

    // 4. Advance the clock
    // Because FS is mocked, there is no "real" IO wait. The promises resolve
    // in the microtask queue, which tickAsync handles automatically.
    await clock.tickAsync(31000);

    // 5. Assert failure
    await assert.rejects(
      promise,
      /Certificate config or certificate file not found after multiple retries/,
    );
  });

  it('should return undefined for non-agent identity certificate', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;
    // Use the non-agentic cert from fixtures
    await fs.promises.writeFile(
      configPath,
      JSON.stringify({
        cert_configs: {workload: {cert_path: NON_AGENTIC_CERT_PATH}},
      }),
    );

    const fingerprint = await getBindCertificateFingerprint();
    assert.strictEqual(fingerprint, undefined);
  });

  it('should return fingerprint for valid agent identity certificate', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;
    await fs.promises.writeFile(
      configPath,
      JSON.stringify({cert_configs: {workload: {cert_path: certPath}}}),
    );
    await fs.promises.writeFile(certPath, AGENTIC_CERT_PEM);

    const cert = new crypto.X509Certificate(AGENTIC_CERT_PEM);
    const expectedFingerprint = crypto
      .createHash('sha256')
      .update(cert.raw)
      .digest('base64url');

    const fingerprint = await getBindCertificateFingerprint();
    assert.strictEqual(fingerprint, expectedFingerprint);
  });

  it('should poll and succeed if files appear late', async () => {
    process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;

    const promise = getBindCertificateFingerprint();

    // Wait a bit, files missing
    await clock.tickAsync(1000);

    // Create config
    await fs.promises.writeFile(
      configPath,
      JSON.stringify({cert_configs: {workload: {cert_path: certPath}}}),
    );

    // Wait more, cert missing
    await clock.tickAsync(1000);

    // Create cert
    await fs.promises.writeFile(certPath, AGENTIC_CERT_PEM);

    // Complete polling
    await clock.tickAsync(1000);

    const cert = new crypto.X509Certificate(AGENTIC_CERT_PEM);
    const expectedFingerprint = crypto
      .createHash('sha256')
      .update(cert.raw)
      .digest('base64url');

    const fingerprint = await promise;
    assert.strictEqual(fingerprint, expectedFingerprint);
  });
});
