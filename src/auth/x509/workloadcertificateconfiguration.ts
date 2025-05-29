import {CertificateConfigFileJson, WorkloadCertPaths} from './x509interfaces';
import {
  CertificateSourceUnavailableError,
  InvalidConfigurationError,
} from './x509errors';

/**
 * Parses the certificate_config.json content to extract workload certificate paths.
 *
 * @param jsonContent The string content of the certificate_config.json file.
 * @param filePathForErrorMessage Optional path of the file, for more descriptive error messages.
 * @returns An object containing the certificate path and private key path.
 * @throws {CertificateSourceUnavailableError} If the workload config is missing.
 * @throws {InvalidConfigurationError} If paths are missing or invalid.
 */
export function parseWorkloadCertificateConfiguration(
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
