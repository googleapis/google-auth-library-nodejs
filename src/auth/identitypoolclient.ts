// Copyright 2021 Google LLC
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

import {
  BaseExternalAccountClient,
  BaseExternalAccountClientOptions,
  ExternalAccountSupplierContext,
} from './baseexternalclient';
import {SnakeToCamelObject, originalOrCamelOptions} from '../util';
import {FileSubjectTokenSupplier} from './filesubjecttokensupplier';
import {UrlSubjectTokenSupplier} from './urlsubjecttokensupplier';

export type SubjectTokenFormatType = 'json' | 'text';

export interface SubjectTokenJsonResponse {
  [key: string]: string;
}

/**
 * Supplier interface for subject tokens. This can be implemented to
 * return a subject token which can then be exchanged for a GCP token by an
 * {@link IdentityPoolClient}.
 */
export interface SubjectTokenSupplier {
  /**
   * Gets a valid subject token for the requested external account identity.
   * Note that these are not cached by the calling {@link IdentityPoolClient},
   * so caching should be including in the implementation.
   * @param context {@link ExternalAccountSupplierContext} from the calling
   *   {@link IdentityPoolClient}, contains the requested audience and subject token type
   *   for the external account identity as well as the transport from the
   *   calling client to use for requests.
   * @return A promise that resolves with the requested subject token string.
   */
  getSubjectToken: (context: ExternalAccountSupplierContext) => Promise<string>;
}

/**
 * Url-sourced/file-sourced credentials json interface.
 * This is used for K8s and Azure workloads.
 */
export interface IdentityPoolClientOptions
  extends BaseExternalAccountClientOptions {
  /**
   * Object containing options to retrieve identity pool credentials. A valid credential
   * source or a subject token supplier must be specified.
   */
  credential_source?: {
    /**
     * The file location to read the subject token from. Either this or a URL
     * should be specified.
     */
    file?: string;
    /**
     * The URL to call to retrieve the subject token. Either this or a file
     * location should be specified.
     */
    url?: string;
    /**
     * Optional headers to send on the request to the specified URL.
     */
    headers?: {
      [key: string]: string;
    };
    /**
     * The format that the subject token is in the file or the URL response.
     * If not provided, will default to reading the text string directly.
     */
    format?: {
      /**
       * The format type. Can either be 'text' or 'json'.
       */
      type: SubjectTokenFormatType;
      /**
       * The field name containing the subject token value if the type is 'json'.
       */
      subject_token_field_name?: string;
    };
  };
  /**
   * The subject token supplier to call to retrieve the subject token to exchange
   * for a GCP access token. Either this or a valid credential source should
   * be specified.
   */
  subject_token_supplier?: SubjectTokenSupplier;
}

/**
 * Defines the Url-sourced and file-sourced external account clients mainly
 * used for K8s and Azure workloads.
 */
export class IdentityPoolClient extends BaseExternalAccountClient {
  private readonly subjectTokenSupplier: SubjectTokenSupplier;

  /**
   * Instantiate an IdentityPoolClient instance using the provided JSON
   * object loaded from an external account credentials file.
   * An error is thrown if the credential is not a valid file-sourced or
   * url-sourced credential or a workforce pool user project is provided
   * with a non workforce audience.
   * @param options The external account options object typically loaded
   *   from the external account JSON credential file. The camelCased options
   *   are aliases for the snake_cased options.
   */
  constructor(
    options:
      | IdentityPoolClientOptions
      | SnakeToCamelObject<IdentityPoolClientOptions>
  ) {
    super(options);

    const opts = originalOrCamelOptions(options as IdentityPoolClientOptions);
    const credentialSource = opts.get('credential_source');
    const subjectTokenSupplier = opts.get('subject_token_supplier');
    // Validate credential sourcing configuration.
    if (!credentialSource && !subjectTokenSupplier) {
      throw new Error(
        'A credential source or subject token supplier must be specified.'
      );
    }
    if (credentialSource && subjectTokenSupplier) {
      throw new Error(
        'Only one of credential source or subject token supplier can be specified.'
      );
    }

    if (subjectTokenSupplier) {
      this.subjectTokenSupplier = subjectTokenSupplier;
      this.credentialSourceType = 'programmatic';
    } else {
      const credentialSourceOpts = originalOrCamelOptions(credentialSource);

      const formatOpts = originalOrCamelOptions(
        credentialSourceOpts.get('format')
      );

      // Text is the default format type.
      const formatType = formatOpts.get('type') || 'text';
      const formatSubjectTokenFieldName = formatOpts.get(
        'subject_token_field_name'
      );

      if (formatType !== 'json' && formatType !== 'text') {
        throw new Error(`Invalid credential_source format "${formatType}"`);
      }
      if (formatType === 'json' && !formatSubjectTokenFieldName) {
        throw new Error(
          'Missing subject_token_field_name for JSON credential_source format'
        );
      }

      const file = credentialSourceOpts.get('file');
      const url = credentialSourceOpts.get('url');
      const headers = credentialSourceOpts.get('headers');
      if (file && url) {
        throw new Error(
          'No valid Identity Pool "credential_source" provided, must be either file or url.'
        );
      } else if (file && !url) {
        this.credentialSourceType = 'file';
        this.subjectTokenSupplier = new FileSubjectTokenSupplier({
          filePath: file,
          formatType: formatType,
          subjectTokenFieldName: formatSubjectTokenFieldName,
        });
      } else if (!file && url) {
        this.credentialSourceType = 'url';
        this.subjectTokenSupplier = new UrlSubjectTokenSupplier({
          url: url,
          formatType: formatType,
          subjectTokenFieldName: formatSubjectTokenFieldName,
          headers: headers,
          additionalGaxiosOptions: IdentityPoolClient.RETRY_CONFIG,
        });
      } else {
        throw new Error(
          'No valid Identity Pool "credential_source" provided, must be either file or url.'
        );
      }
    }
  }

  /**
   * Triggered when a external subject token is needed to be exchanged for a GCP
   * access token via GCP STS endpoint. Gets a subject token by calling
   * the configured {@link SubjectTokenSupplier}
   * @return A promise that resolves with the external subject token.
   */
  async retrieveSubjectToken(): Promise<string> {
    return this.subjectTokenSupplier.getSubjectToken(this.supplierContext);
  }
}
