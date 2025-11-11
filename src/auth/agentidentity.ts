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

import * as crypto from 'crypto';
import * as fs from 'fs';
import {log as makeLog} from 'google-logging-utils';

const log = makeLog('google-auth-library:agentidentity');

const CERT_CONFIG_ENV_VAR = 'GOOGLE_API_CERTIFICATE_CONFIG';
const PREVENT_SHARING_ENV_VAR =
  'GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES';

const AGENT_IDENTITY_SPIFFE_PATTERNS = [
  /^agents\.global\.org-\d+\.system\.id\.goog$/,
  /^agents\.global\.proj-\d+\.system\.id\.goog$/,
];

// Polling configuration
// Total timeout: 30 seconds
// Phase 1: 5 seconds of fast polling (every 0.1s) = 50 cycles
// Phase 2: 25 seconds of slow polling (every 0.5s) = 50 cycles
const FAST_POLL_INTERVAL_MS = 100;
const FAST_POLL_CYCLES = 50;
const SLOW_POLL_INTERVAL_MS = 500;
const SLOW_POLL_CYCLES = 50;

/**
 * Interface for the certificate configuration file.
 * Matches the structure expected by CertificateSubjectTokenSupplier but strictly for Workload.
 */
interface CertificateConfigFile {
  cert_configs: {
    workload?: {
      cert_path: string;
    };
  };
}

/**
 * Helper function to delay execution.
 * @param ms Time to sleep in milliseconds.
 */
async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retrieves the path to the agent identity certificate by polling the configuration file.
 * @returns The path to the certificate file, or null if not configured.
 * @throws Error if the configuration or certificate file cannot be found after the timeout.
 */
async function getAgentIdentityCertificatePath(): Promise<string | null> {
  const configPath = process.env[CERT_CONFIG_ENV_VAR];
  if (!configPath) {
    return null;
  }

  let hasLoggedWarning = false;

  for (let i = 0; i < FAST_POLL_CYCLES + SLOW_POLL_CYCLES; i++) {
    try {
      if (fs.existsSync(configPath)) {
        const configContent = await fs.promises.readFile(configPath, 'utf-8');
        const config = JSON.parse(configContent) as CertificateConfigFile;
        const certPath = config.cert_configs?.workload?.cert_path;

        if (certPath && fs.existsSync(certPath)) {
          return certPath;
        }
      }
    } catch (error) {
      // Ignore errors during polling, will retry.
    }

    if (!hasLoggedWarning) {
      log.warn(
        `Certificate config file not found at ${configPath} (from ${CERT_CONFIG_ENV_VAR} environment variable). ` +
          'Retrying for up to 30 seconds.',
      );
      hasLoggedWarning = true;
    }

    const interval =
      i < FAST_POLL_CYCLES ? FAST_POLL_INTERVAL_MS : SLOW_POLL_INTERVAL_MS;
    await sleep(interval);
  }

  throw new Error(
    'Certificate config or certificate file not found after multiple retries. ' +
      'Token binding protection is failing. You can turn off this protection by setting ' +
      `${PREVENT_SHARING_ENV_VAR} to false to fall back to unbound tokens.`,
  );
}

/**
 * Parses a PEM-encoded certificate.
 * @param certBuffer The certificate data.
 * @returns The parsed X509Certificate object.
 */
function parseCertificate(certBuffer: Buffer): crypto.X509Certificate {
  return new crypto.X509Certificate(certBuffer);
}

/**
 * Checks if the certificate is an Agent Identity certificate by inspecting the SPIFFE ID in the SAN.
 * @param cert The parsed certificate.
 * @returns True if it matches an Agent Identity pattern.
 */
function isAgentIdentityCertificate(cert: crypto.X509Certificate): boolean {
  const san = cert.subjectAltName;
  if (!san) {
    return false;
  }

  // Node's X509Certificate.subjectAltName returns a string like "URI:spiffe://..., DNS:..."
  // We use a regex to find all SPIFFE URIs and check their trust domains.
  const uriMatches = san.matchAll(/URI:spiffe:\/\/([^/]+)\/.*?(?:,|$)/g);
  for (const match of uriMatches) {
    const trustDomain = match[1];
    for (const pattern of AGENT_IDENTITY_SPIFFE_PATTERNS) {
      if (pattern.test(trustDomain)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Calculates the unpadded base64url-encoded SHA256 fingerprint of the certificate.
 * @param cert The parsed certificate.
 * @returns The fingerprint string.
 */
function calculateCertificateFingerprint(cert: crypto.X509Certificate): string {
  return crypto.createHash('sha256').update(cert.raw).digest('base64url');
}

/**
 * Main entry point to get the bind certificate fingerprint if appropriate.
 * Checks opt-out env var, polls for cert, validates it's an Agent Identity cert, and returns the fingerprint.
 * @returns The fingerprint if a bound token should be requested, otherwise undefined.
 */
export async function getBindCertificateFingerprint(): Promise<
  string | undefined
> {
  // 1. Check opt-out
  if (process.env[PREVENT_SHARING_ENV_VAR]?.toLowerCase() === 'false') {
    return undefined;
  }

  // 2. Get certificate path (polling if necessary)
  const certPath = await getAgentIdentityCertificatePath();
  if (!certPath) {
    return undefined;
  }

  // 3. Read and parse certificate
  // We use fs.promises.readFile here. The existence was checked in polling,
  // but it might have disappeared or be unreadable.
  // We let standard IO errors propagate if it fails now after polling succeeded.
  const certBuffer = await fs.promises.readFile(certPath);
  const cert = parseCertificate(certBuffer);

  // 4. Check if it's an Agent Identity certificate
  if (!isAgentIdentityCertificate(cert)) {
    return undefined;
  }

  // 5. Calculate and return fingerprint
  return calculateCertificateFingerprint(cert);
}
