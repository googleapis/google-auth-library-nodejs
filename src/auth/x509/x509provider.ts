import * as fs from 'fs';
import * as https from 'https';
import * as path from 'path';
import * as os from 'os';

/**
 * Custom error thrown when a certificate source is unavailable or improperly configured.
 */
export class CertificateSourceUnavailableError extends Error {
  constructor(
    message: string,
    public cause?: Error,
  ) {
    super(message);
    this.name = 'CertificateSourceUnavailableError';
    // Ensure the prototype chain is correctly set for custom errors
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
 * Interface for the paths extracted from the workload configuration.
 */
interface WorkloadCertPaths {
  certPath: string;
  privateKeyPath: string;
}

/**
 * Options for creating an X509CredentialsProvider instance.
 */
export interface X509CredentialsProviderOptions {
  /**
   * Optional override path for the certificate_config.json file.
   */
  certConfigPathOverride?: string;
}

const CERTIFICATE_CONFIGURATION_ENV_VARIABLE = 'GOOGLE_API_CERTIFICATE_CONFIG';
const WELL_KNOWN_CERTIFICATE_CONFIG_FILE = 'certificate_config.json';
const CLOUDSDK_CONFIG_DIRECTORY = 'gcloud';

export class X509CredentialsProvider {
  private readonly certConfigPathOverride?: string;

  constructor(options?: X509CredentialsProviderOptions) {
    this.certConfigPathOverride = options?.certConfigPathOverride;
  }

  /**
   * Parses the certificate_config.json content to extract workload certificate paths.
   * @param jsonContent The string content of the certificate_config.json file.
   * @param filePathForErrorMessage Optional path of the file, for more descriptive error messages.
   * @returns An object containing the certificate path and private key path.
   */
  private parseCertificateConfiguration(
    jsonContent: string,
    filePathForErrorMessage?: string,
  ): WorkloadCertPaths {
    let parsedConfig: CertificateConfigFileJson;
    try {
      parsedConfig = JSON.parse(jsonContent) as CertificateConfigFileJson;
    } catch (e) {
      throw new InvalidConfigurationError(
        `Failed to parse certificate configuration${filePathForErrorMessage ? ` from ${filePathForErrorMessage}` : ''}: ${(e as Error).message}`,
      );
    }

    const certConfigs = parsedConfig.cert_configs;
    if (!certConfigs || typeof certConfigs !== 'object') {
      throw new InvalidConfigurationError(
        `The "cert_configs" object must be provided in the certificate configuration${filePathForErrorMessage ? ` from ${filePathForErrorMessage}` : ''}.`,
      );
    }

    const workloadConfig = certConfigs.workload;
    if (!workloadConfig || typeof workloadConfig !== 'object') {
      throw new CertificateSourceUnavailableError(
        `A "workload" certificate configuration must be provided in the "cert_configs" object${filePathForErrorMessage ? ` from ${filePathForErrorMessage}` : ''}.`,
      );
    }

    const certPath = workloadConfig.cert_path;
    if (!certPath || typeof certPath !== 'string' || certPath.trim() === '') {
      throw new InvalidConfigurationError(
        `The "cert_path" field must be provided and be a non-empty string in the workload certificate configuration${filePathForErrorMessage ? ` from ${filePathForErrorMessage}` : ''}.`,
      );
    }

    const privateKeyPath = workloadConfig.key_path;
    if (
      !privateKeyPath ||
      typeof privateKeyPath !== 'string' ||
      privateKeyPath.trim() === ''
    ) {
      throw new InvalidConfigurationError(
        `The "key_path" field must be provided and be a non-empty string in the workload certificate configuration${filePathForErrorMessage ? ` from ${filePathForErrorMessage}` : ''}.`,
      );
    }

    return {
      certPath: certPath,
      privateKeyPath: privateKeyPath,
    };
  }

  /**
   * Locates and reads the certificate_config.json file, then parses it.
   * This combines parts of the Java X509Provider's constructor and getWorkloadCertificateConfiguration.
   * @returns The paths for the certificate and private key.
   */
  private getWorkloadCertificatePaths(): WorkloadCertPaths {
    const configFilePath = this.resolveCertificateConfigFilePath(); // This will find the file or throw

    let fileContents;
    try {
      fileContents = fs.readFileSync(configFilePath, 'utf-8');
    } catch (err) {
      throw new CertificateSourceUnavailableError(
        `Failed to read certificate config file: ${configFilePath}`,
        err instanceof Error ? err : new Error(String(err)),
      );
    }
    return this.parseCertificateConfiguration(fileContents, configFilePath);
  }

  /**
   * Resolves the path to the certificate_config.json file by checking override,
   * environment variable, and well-known locations.
   * @returns The resolved file path.
   * @throws {CertificateSourceUnavailableError} If the file is not found or invalid.
   */
  private resolveCertificateConfigFilePath(): string {
    // 1. Check override path if provided during instantiation
    if (this.certConfigPathOverride) {
      if (this.isValidFile(this.certConfigPathOverride)) {
        return this.certConfigPathOverride;
      }
      throw new CertificateSourceUnavailableError(
        `Override certificate config path is invalid or not a file: ${this.certConfigPathOverride}`,
      );
    }

    // 2. Check GOOGLE_API_CERTIFICATE_CONFIG environment variable
    const envPath = process.env[CERTIFICATE_CONFIGURATION_ENV_VARIABLE];
    if (envPath) {
      if (this.isValidFile(envPath)) {
        return envPath;
      }
      throw new CertificateSourceUnavailableError(
        `Environment variable ${CERTIFICATE_CONFIGURATION_ENV_VARIABLE} points to an invalid path or is not a file: ${envPath}`,
      );
    }

    // 3. Check well-known gcloud location
    const wellKnownPath = this.getWellKnownCertificateConfigFileLocation();
    if (this.isValidFile(wellKnownPath)) {
      return wellKnownPath;
    }

    throw new CertificateSourceUnavailableError(
      'Certificate configuration file not found. Checked override, environment variable ' +
        `'${CERTIFICATE_CONFIGURATION_ENV_VARIABLE}', and well-known gcloud path (e.g., '${wellKnownPath}').`,
    );
  }

  /**
   * Helper to check if a path points to a valid file.
   */
  private isValidFile(filePath: string): boolean {
    try {
      return fs.existsSync(filePath) && fs.lstatSync(filePath).isFile();
    } catch (e) {
      // Path might be malformed, causing existsSync or lstatSync to throw.
      return false;
    }
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
    } else if (process.platform === 'win32') {
      // Mimics getOsName().indexOf("windows") >= 0
      const appData = process.env['APPDATA'];
      // If APPDATA is not set, behavior might be undefined, path.join handles it.
      cloudConfigDir = path.join(appData || '', CLOUDSDK_CONFIG_DIRECTORY);
    } else {
      const homeDir = os.homedir(); // Mimics getProperty("user.home", "")
      // Default to .config in home directory for Linux/macOS
      cloudConfigDir = path.join(homeDir, '.config', CLOUDSDK_CONFIG_DIRECTORY);
    }
    return path.join(cloudConfigDir, WELL_KNOWN_CERTIFICATE_CONFIG_FILE);
  }

  /**
   * Creates and returns an https.Agent configured for mTLS.
   * @returns A Promise that resolves with an mTLS-configured https.Agent.
   */
  public async createMtlsHttpsAgent(): Promise<https.Agent> {
    const workloadPaths = this.getWorkloadCertificatePaths();

    try {
      const key = fs.readFileSync(workloadPaths.privateKeyPath);
      const cert = fs.readFileSync(workloadPaths.certPath);

      // In Node.js, an https.Agent is configured directly with key and cert.
      //TODO: pjiyer verify if this generates the MLTS agent with the certificates
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
}
