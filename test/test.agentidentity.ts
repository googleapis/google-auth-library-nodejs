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

const AGENTIC_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUCYeV4dwM29T5yucwWrSWlOC9wwYwDQYJKoZIhvcNAQEL
BQAwIjEgMB4GA1UEAwwXVGVzdCBTUElGRkUgQ2VydGlmaWNhdGUwHhcNMjUxMTA3
MDEyMjQ4WhcNMzUxMTA1MDEyMjQ4WjAiMSAwHgYDVQQDDBdUZXN0IFNQSUZGRSBD
ZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANDr1Bzo
KtzIZB35acQ+mpk6yScf59AnwHjjgNCMbC7kq2DSUfQzTlu9Kd0uUB6O7DmJ73D8
Pge4XLE/Q1B6dI6DzJx7lhPoC1BiQFUGJ4Cu+TbbdlK3RiXNAZYjIj9UKP7DejCY
WRgFB+PYyLczEkByvU9cy7Z9Uuufsn6LnYu7qOG+DcRSE41ThurZxQ14OWvLfjZm
lhZXam4VBBli8Qku8qFIALe78kpy+hp2YCRnK84amATwPpGprRACp9WVka2JDYKD
LY0OoYlyAQel6960aS11N3/2v0cvx03/LM5+Yj+DTvdyb2Mk/NVeRIKo8cM5YwPn
sTLCf1cdxJvseRMCAwEAAaNsMGowSQYDVR0RBEIwQIY+c3BpZmZlOi8vYWdlbnRz
Lmdsb2JhbC5wcm9qLTEyMzQ1LnN5c3RlbS5pZC5nb29nL3Rlc3Qtd29ya2xvYWQw
HQYDVR0OBBYEFPvn+KXBcrYCmAMopkghUczUx/IkMA0GCSqGSIb3DQEBCwUAA4IB
AQCbwd9RMFkr1C9AEgnLMWd1l9ciBbK0t1Sydu3eA0SNm2w6E58ih8O+huo6eGsM
7z0E4i7YuaHnTdah/lPMqd75YRO57GSRbvi2g+yPyw6XdFl9HCHwF4WARdTF4Nkf
1c1WstvBXb24PSSQQdy9un72ZG6f9fSVQrko6hchv8Rg6yyBTFE8APPkeMR/EJtV
cnXg4CgsQIPHxJGQrhNvQhF7VLZePlTass4bqTqTYXwAte2jX/KW3qlW/t/v4AJe
/q+pcXmNIvwRpT8zYA5tJHIDVJ+v9pWZA+nhoD9Qtr7FVHfB4mdNuFv7bMPoXN0+
mCPzP08MnjgbX7zRETVlblrx
-----END CERTIFICATE-----`;

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

//   it('should fail if cert file does not appear within timeout', async () => {
//     process.env.GOOGLE_API_CERTIFICATE_CONFIG = configPath;
//     await fs.promises.writeFile(
//       configPath,
//       JSON.stringify({
//         cert_configs: {
//           workload: {
//             cert_path: certPath,
//           },
//         },
//       }),
//     );

//     const promise = getBindCertificateFingerprint();
//     await clock.tickAsync(31000);

//     await assert.rejects(
//       promise,
//       /Certificate config or certificate file not found after multiple retries/,
//     );
//   });

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
