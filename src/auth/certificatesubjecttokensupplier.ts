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

import {GaxiosOptions} from 'gaxios';
import {SubjectTokenSupplier} from './identitypoolclient';
import {AuthClient} from 'google-auth-library';
import {getWellKnownCertificateConfigFileLocation, isValidFile} from '../util';
import * as fs from 'fs';
import {X509Certificate} from 'crypto';
import * as https from 'https';

// --- Constants ---
export const CERTIFICATE_CONFIGURATION_ENV_VARIABLE =
  'GOOGLE_API_CERTIFICATE_CONFIG';

// --- Custom Errors ---

/**
 * Thrown when the certificate source cannot be located or accessed.
 */
export class CertificateSourceUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateSourceUnavailableError';
  }
}

/**
 * Thrown for invalid configuration that is not related to file availability.
 */
export class InvalidConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidConfigurationError';
  }
}

// --- Interfaces ---

/**
 * Defines options for creating a {@link CertificateSubjectTokenSupplier}.
 */
export interface CertificateSubjectTokenSupplierOptions {
  /**
   * If true, uses the default well-known location for the certificate config.
   * Either this or `certificateConfigLocation` must be provided.
   */
  useDefaultCertificateConfig?: boolean;
  /**
   * The file path to the certificate configuration JSON file.
   * Required if `useDefaultCertificateConfig` is not true.
   */
  certificateConfigLocation?: string;
  /**
   * The file path to the trust chain (PEM format). If not provided,
   * only the leaf certificate will be sent.
   */
  trustChainPath?: string;
}

/**
 * Represents the "workload" block within the certificate configuration file.
 * @internal
 */
interface WorkloadCertConfigJson {
  cert_path: string;
  key_path: string;
}

/**
 * Represents the structure of the certificate_config.json file.
 * @internal
 */
interface CertificateConfigFileJson {
  version: number;
  cert_configs: {
    workload?: WorkloadCertConfigJson;
  };
}

// --- Main Class ---

/**
 * A subject token supplier that uses a client certificate for authentication.
 * It provides the certificate chain as the subject token for identity federation.
 */
export class CertificateSubjectTokenSupplier implements SubjectTokenSupplier {
  private readonly certificateConfigPath: string;
  private readonly trustChainPath?: string;
  private readonly certPath: string;
  private readonly keyPath: string;

  /**
   * Initializes a new instance of the CertificateSubjectTokenSupplier.
   * @param opts The configuration options for the supplier.
   */
  constructor(opts: CertificateSubjectTokenSupplierOptions) {
    if (!opts.useDefaultCertificateConfig && !opts.certificateConfigLocation) {
      throw new InvalidConfigurationError(
        'Either `useDefaultCertificateConfig` must be true or a `certificateConfigLocation` must be provided.',
      );
    }
    if (opts.useDefaultCertificateConfig && opts.certificateConfigLocation) {
      throw new InvalidConfigurationError(
        'Both `useDefaultCertificateConfig` and `certificateConfigLocation` cannot be provided.',
      );
    }
    this.trustChainPath = opts.trustChainPath;
    this.certificateConfigPath = this.#resolveCertificateConfigFilePath(
      opts.certificateConfigLocation,
    );
    ({certPath: this.certPath, keyPath: this.keyPath} =
      this.#getWorkloadCertificatePaths(this.certificateConfigPath));
  }

  /**
   * Creates an HTTPS agent configured with the client certificate and private key for mTLS.
   * @returns An mTLS-configured https.Agent.
   */
  public createMtlsHttpsAgent(): https.Agent {
    try {
      const cert = fs.readFileSync(this.certPath);
      const key = fs.readFileSync(this.keyPath);
      return new https.Agent({key, cert});
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CertificateSourceUnavailableError(
        `Failed to read certificate or key file: ${message}`,
      );
    }
  }

  /**
   * Constructs the subject token, which is the base64-encoded certificate chain.
   * @returns A promise that resolves with the subject token.
   */
  public async getSubjectToken(): Promise<string> {
    const opts: GaxiosOptions = {method: 'GET'};
    AuthClient.setMethodName(opts, 'getSubjectToken');

    // The "subject token" in this context is the processed certificate chain.
    return this.#processChainFromPaths();
  }

  /**
   * Resolves the absolute path to the certificate configuration file
   * by checking an explicit path, an environment variable, and a well-known location.
   * @param overridePath An optional path to check first.
   * @returns The resolved file path.
   */
  #resolveCertificateConfigFilePath(overridePath?: string): string {
    // 1. Check for the override path from constructor options.
    if (overridePath) {
      if (isValidFile(overridePath)) {
        return overridePath;
      }
      throw new CertificateSourceUnavailableError(
        `Provided certificate config path is invalid: ${overridePath}`,
      );
    }

    // 2. Check the standard environment variable.
    const envPath = process.env[CERTIFICATE_CONFIGURATION_ENV_VARIABLE];
    if (envPath) {
      if (isValidFile(envPath)) {
        return envPath;
      }
      throw new CertificateSourceUnavailableError(
        `Path from environment variable "${CERTIFICATE_CONFIGURATION_ENV_VARIABLE}" is invalid: ${envPath}`,
      );
    }

    // 3. Check the well-known gcloud config location.
    const wellKnownPath = getWellKnownCertificateConfigFileLocation();
    if (isValidFile(wellKnownPath)) {
      return wellKnownPath;
    }

    // 4. If none are found, throw an error.
    throw new CertificateSourceUnavailableError(
      'Could not find certificate configuration file. Searched override path, ' +
        `the "${CERTIFICATE_CONFIGURATION_ENV_VARIABLE}" env var, and the gcloud path (${wellKnownPath}).`,
    );
  }

  /**
   * Reads and parses the certificate config file to extract the certificate and key paths.
   * @param configPath The path to the certificate configuration JSON file.
   * @returns An object containing the certificate and key paths.
   */
  #getWorkloadCertificatePaths(configPath: string): {
    certPath: string;
    keyPath: string;
  } {
    let fileContents: string;
    try {
      fileContents = fs.readFileSync(configPath, 'utf8');
    } catch (err) {
      throw new CertificateSourceUnavailableError(
        `Failed to read certificate config file at: ${configPath}`,
      );
    }

    try {
      const config = JSON.parse(fileContents) as CertificateConfigFileJson;
      const certPath = config?.cert_configs?.workload?.cert_path;
      const keyPath = config?.cert_configs?.workload?.key_path;

      if (!certPath || !keyPath) {
        throw new InvalidConfigurationError(
          `Certificate config file (${configPath}) is missing required "cert_path" or "key_path" in the workload config.`,
        );
      }
      return {certPath, keyPath};
    } catch (e) {
      if (e instanceof InvalidConfigurationError) throw e;
      throw new InvalidConfigurationError(
        `Failed to parse certificate config from ${configPath}: ${
          (e as Error).message
        }`,
      );
    }
  }

  /**
   * Reads the leaf certificate and trust chain, combines them,
   * and returns a JSON array of base64-encoded certificates.
   * @returns A stringified JSON array of the certificate chain.
   */
  #processChainFromPaths(): string {
    if (!this.trustChainPath) {
      // If no trust chain is provided, just use the leaf certificate.
      try {
        const leafPem = fs.readFileSync(this.certPath, 'utf8');
        const leafCert = new X509Certificate(leafPem);
        return JSON.stringify([leafCert.raw.toString('base64')]);
      } catch (err) {
        throw new CertificateSourceUnavailableError(
          `Failed to read or parse leaf certificate at ${this.certPath}: ${
            (err as Error).message
          }`,
        );
      }
    }

    try {
      // Read both the leaf and the chain files.
      const leafPem = fs.readFileSync(this.certPath, 'utf8');
      const chainPems = fs.readFileSync(this.trustChainPath, 'utf8');

      // Parse all certificates.
      const leafCert = new X509Certificate(leafPem);
      const chainCerts =
        chainPems
          .match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g)
          ?.map(pem => new X509Certificate(pem)) ?? [];

      // Check if the leaf certificate is already in the provided chain.
      const leafIndex = chainCerts.findIndex(chainCert =>
        leafCert.raw.equals(chainCert.raw),
      );

      let finalChain: X509Certificate[];

      if (leafIndex === -1) {
        // Leaf not found, so prepend it to the chain.
        finalChain = [leafCert, ...chainCerts];
      } else if (leafIndex === 0) {
        // Leaf is already the first element, so the chain is correctly ordered.
        finalChain = chainCerts;
      } else {
        // Leaf is in the chain but not at the top, which is invalid.
        throw new InvalidConfigurationError(
          `Leaf certificate exists in the trust chain but is not the first entry (found at index ${leafIndex}).`,
        );
      }

      return JSON.stringify(
        finalChain.map(cert => cert.raw.toString('base64')),
      );
    } catch (err) {
      if (err instanceof InvalidConfigurationError) throw err;
      throw new CertificateSourceUnavailableError(
        `Failed to process certificate chain: ${(err as Error).message}`,
      );
    }
  }
}
