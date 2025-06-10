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
import {ExternalAccountSupplierContext} from './baseexternalclient';
import {SubjectTokenSupplier} from './identitypoolclient';
import {AuthClient} from 'google-auth-library';
import {isValidFile} from '../util';
import path = require('path');
import * as os from 'os';
import * as fs from 'fs';
import {readFileSync} from 'fs';
import {X509Certificate} from 'crypto';
import * as https from 'https';

const CERTIFICATE_CONFIGURATION_ENV_VARIABLE = 'GOOGLE_API_CERTIFICATE_CONFIG';
const WELL_KNOWN_CERTIFICATE_CONFIG_FILE = 'certificate_config.json';
const CLOUDSDK_CONFIG_DIRECTORY = 'gcloud';

/**
 * Interface that defines options used to build a {@link CertificateSubjectTokenSupplier}
 */
export interface CertificateSubjectTokenSupplierOptions {
  /**
   * Specify whether the certificate config should be used from the default location
   * either this or the certificate_config_location must be provided
   */
  useDefaultCertificateConfig?: boolean;
  /**
   * Location to fetch certificate config from in case default config is not to be used.
   * either this or use_default_certificate_config=true should be provided
   */
  certificateConfigLocation?: string;
  /**
   * Location to fetch trust chain from to send to STS endpoint.
   * in case no location is provided, we will just send the leaf certificate as the
   * trust chain
   */
  trustChainPath?: string;
}

/**
 * Interface representing the "workload" block within the cert_configs object
 * in certificate_config.json, as described in the design document.
 */
interface WorkloadCertConfigJson {
  cert_path: string;
  key_path: string;
}

/**
 * Interface representing the overall structure of the certificate_config.json file.
 */
interface CertificateConfigFileJson {
  version: number;
  cert_configs: {
    workload?: WorkloadCertConfigJson;
    // Other potential configurations could be added here in the future.
  };
}

/**
 * Internal subject token supplier implementation used when a certificate
 * is configured in the credential configuration used to build an {@link IdentityPoolClient}
 */
export class CertificateSubjectTokenSupplier implements SubjectTokenSupplier {
  private readonly useDefaultCertificateConfig?: boolean;
  private readonly certificateConfigLocation?: string;
  private readonly trustChainPath?: string;
  private readonly certificateConfigPath: string;
  certPath?: string;
  keyPath?: string;

  /**
   * Instantiates a new certificate based subject token supplier.
   * @param opts The certificate subject token supplier options to build the supplier
   *   with.
   */
  constructor(opts: CertificateSubjectTokenSupplierOptions) {
    this.useDefaultCertificateConfig = opts.useDefaultCertificateConfig
      ? true
      : false;
    this.certificateConfigLocation = opts.certificateConfigLocation;
    this.trustChainPath = opts.trustChainPath;
    this.certificateConfigPath = this.#resolveCertificateConfigFilePath();
    this.#getWorkloadCertificatePaths(this.certificateConfigPath);
  }

  /**
   * Reads the certificate_config.json file,
   * sets the paths for the certificate and private key.
   */
  #getWorkloadCertificatePaths(certificateConfigPath: string) {
    let fileContents;
    try {
      fileContents = fs.readFileSync(certificateConfigPath, 'utf-8');
    } catch (err) {
      throw new CertificateSourceUnavailableError(
        `Failed to read certificate config file: ${certificateConfigPath}`,
      );
    }

    let parsedConfig: CertificateConfigFileJson;
    try {
      parsedConfig = JSON.parse(fileContents) as CertificateConfigFileJson;
      const certConfigs = parsedConfig.cert_configs;
      const workloadConfig = certConfigs.workload;
      this.certPath = workloadConfig?.cert_path;
      this.keyPath = workloadConfig?.key_path;
    } catch (e) {
      throw new InvalidConfigurationError(
        `Failed to parse certificate configuration${certificateConfigPath ? ` from ${certificateConfigPath}` : ''}: ${(e as Error).message}`,
      );
    }
  }

  #resolveCertificateConfigFilePath(): string {
    // 1. Check override path if provided during instantiation
    if (this.certificateConfigLocation) {
      if (isValidFile(this.certificateConfigLocation)) {
        return this.certificateConfigLocation;
      }
      throw new CertificateSourceUnavailableError(
        `Override certificate config path is invalid or not a file: ${this.certificateConfigLocation}`,
      );
    }

    // 2. Check GOOGLE_API_CERTIFICATE_CONFIG environment variable
    const envPath = process.env[CERTIFICATE_CONFIGURATION_ENV_VARIABLE];
    if (envPath) {
      if (isValidFile(envPath)) {
        return envPath;
      }
      throw new CertificateSourceUnavailableError(
        `Environment variable ${CERTIFICATE_CONFIGURATION_ENV_VARIABLE} points to an invalid path or is not a file: ${envPath}`,
      );
    }

    // 3. Check well-known gcloud location
    const wellKnownPath = this.getWellKnownCertificateConfigFileLocation();
    if (isValidFile(wellKnownPath)) {
      return wellKnownPath;
    }

    throw new CertificateSourceUnavailableError(
      'Certificate configuration file not found. Checked override, environment variable ' +
        `'${CERTIFICATE_CONFIGURATION_ENV_VARIABLE}', and well-known gcloud path (e.g., '${wellKnownPath}').`,
    );
  }

  /**
   * Determines the well-known gcloud location for certificate_config.json.
   */
  private getWellKnownCertificateConfigFileLocation(): string {
    let cloudConfigDir: string;
    // Gcloud's standard environment variable for its configuration root.
    const envCloudSdkConfig = process.env['CLOUDSDK_CONFIG'];

    if (envCloudSdkConfig) {
      cloudConfigDir = envCloudSdkConfig;
    } else if (this._isWindows()) {
      const appData = process.env['APPDATA'];
      cloudConfigDir = path.join(appData || '', CLOUDSDK_CONFIG_DIRECTORY);
    } else {
      // Linux or Mac
      const home = process.env['HOME'];
      cloudConfigDir = path.join(
        home || '',
        '.config',
        CLOUDSDK_CONFIG_DIRECTORY,
      );
    }
    return path.join(cloudConfigDir, WELL_KNOWN_CERTIFICATE_CONFIG_FILE);
  }

  /**
   * Determines whether the current operating system is Windows.
   * @api private
   */
  private _isWindows() {
    const sys = os.platform();
    if (sys && sys.length >= 3) {
      if (sys.substring(0, 3).toLowerCase() === 'win') {
        return true;
      }
    }
    return false;
  }

  #processChainFromPaths(leafCertPath: string, trustChainPath: string): string {
    //todo pjiyer
    // What to do if trustChainPath doesn't have a valid file?
    // what to do if leafCertPath doesn't have a valid file? -> Throw!

    // 1. Read file contents from the provided paths
    const leafPem = readFileSync(leafCertPath, 'utf8');
    const chainPems = readFileSync(trustChainPath, 'utf8');

    // 2. Parse all certificates
    const leafCert = new X509Certificate(leafPem);
    const originalChainArray =
      chainPems.match(
        /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g,
      ) || [];
    const chainCerts = originalChainArray.map(pem => new X509Certificate(pem));

    // 3. Find the index of the leaf certificate in the chain
    const leafIndex = chainCerts.findIndex(chainCert =>
      leafCert.raw.equals(chainCert.raw),
    );

    // 4. Apply the logic based on whether the leaf was found
    if (leafIndex !== -1) {
      if (leafIndex === 0) {
        // Leaf certificate already exists at the top of the chain so we just return
        return originalChainArray.join('\n');
      } else {
        throw new CertificateSourceUnavailableError(
          'Leaf certificate exists in the chain but is not at the top (found at index ${leafIndex}).',
        );
      }
    } else {
      //Leaf certificate not found in chain. Adding it to the top.
      return [leafPem.trim(), ...originalChainArray].join('\n');
    }
  }

  /**
   * Creates and returns an https.Agent configured for mTLS.
   * @returns An mTLS-configured https.Agent.
   */
  public createMtlsHttpsAgent(): https.Agent {
    try {
      if (!this.certPath || !this.keyPath) {
        throw new CertificateSourceUnavailableError(
          'Cert path or keyPath is invalid',
        );
      }
      // Correctly read the certificate and key files.
      const cert = fs.readFileSync(this.certPath);
      const key = fs.readFileSync(this.keyPath);

      // Return the agent directly.
      return new https.Agent({
        key: key,
        cert: cert,
      });
    } catch (err) {
      // This wraps errors from reading the actual cert/key files.
      throw new Error(
        `Failed to read certificate or key file specified in configuration: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  /**
   * Sends a GET request to the URL provided in the constructor and resolves
   * with the returned external subject token.
   * @param context {@link ExternalAccountSupplierContext} from the calling
   *   {@link IdentityPoolClient}, contains the requested audience and subject
   *   token type for the external account identity. Not used.
   */
  async getSubjectToken(
    context: ExternalAccountSupplierContext,
  ): Promise<string> {
    const opts: GaxiosOptions = {
      method: 'GET',
    };
    AuthClient.setMethodName(opts, 'getSubjectToken');
    //1. Resolve the path for the certificate_config.
    //2. Read Certificate and Key from certificate_config.
    //3. Read TrustChainFile if needed, build the trustChain and add to subject token.

    //TODO pjiyer: review this code for veracity.
    // if (!this.certPath || !this.trustChainPath || !this.keyPath) {
    //   throw new CertificateSourceUnavailableError(
    //     'Cert path or trust chain path or keyPath is invalid',
    //   );
    // }
    // const trustChain = this.#processChainFromPaths(
    //   this.certPath,
    //   this.trustChainPath,
    // );

    // if (!isValidFile(this.keyPath)) {
    //   throw new CertificateSourceUnavailableError(
    //     'Cert path or trust chain path or keyPath is invalid',
    //   );
    // }

    // const key = fs.readFileSync(this.keyPath);

    if (!this.certPath) {
      throw new CertificateSourceUnavailableError(
        'Cert path or trust chain path or keyPath is invalid',
      );
    }
    const cert = new X509Certificate(fs.readFileSync(this.certPath));
    const encodedCert = cert.raw.toString('base64');
    const certChain = [encodedCert];
    const subjectToken = JSON.stringify(certChain /*, null, 2*/);
    return subjectToken;
  }
}

/**
 * Error type to capture when something is wrong while
 * getting the STS token from the certificate.
 */
export class CertificateSourceUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Custom error for invalid configuration issues not specifically about unavailability.
 */
export class InvalidConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidConfigurationError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
