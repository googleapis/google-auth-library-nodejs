export interface WorkloadCertPaths {
  certPath: string;
  privateKeyPath: string;
}

export interface WorkloadCertConfigJson {
  // Matches the "workload" object
  cert_path: string;
  key_path: string;
}

export interface CertificateConfigFileJson {
  // Matches the overall certificate_config.json
  version: number; // As per the design document
  cert_configs: {
    workload?: WorkloadCertConfigJson;
  };
}
