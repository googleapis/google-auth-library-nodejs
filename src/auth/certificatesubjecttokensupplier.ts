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
 * Internal subject token supplier implementation used when a certificate
 * is configured in the credential configuration used to build an {@link IdentityPoolClient}
 */
export class CertificateSubjectTokenSupplier implements SubjectTokenSupplier {
  private readonly useDefaultCertificateConfig?: boolean;
  private readonly certificateConfigLocation?: string;
  private readonly trustChainPath?: string;

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
    if (!this.useDefaultCertificateConfig && !this.certificateConfigLocation) {
      throw new CertificateSourceUnavailableError(
        'Error creating subject token: either use_default_certificate_config==true or a valid certificate_config_location must be provided',
      );
    }
    this.trustChainPath = opts.trustChainPath;
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

    const subjectToken = '';
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
