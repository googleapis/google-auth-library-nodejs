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

import {GaxiosOptions} from 'gaxios';
import * as fs from 'fs';
import {promisify} from 'util';

import {
  BaseExternalAccountClient,
  BaseExternalAccountClientOptions,
} from './baseexternalclient';
import {RefreshOptions} from './oauth2client';

// fs.readfile is undefined in browser karma tests causing
// `npm run browser-test` to fail as test.oauth2.ts imports this file via
// src/index.ts.
// Fallback to void function to avoid promisify throwing a TypeError.
const readFile = promisify(fs.readFile ?? (() => {}));
const realpath = promisify(fs.realpath ?? (() => {}));
const lstat = promisify(fs.lstat ?? (() => {}));

type SubjectTokenFormatType = 'json' | 'text';

interface SubjectTokenJsonResponse {
  [key: string]: string;
}

/**
 * Url-sourced/file-sourced credentials json interface.
 * This is used for K8s and Azure workloads.
 */
export interface IdentityPoolClientOptions
  extends BaseExternalAccountClientOptions {
  credential_source: {
    file?: string;
    url?: string;
    headers?: {
      [key: string]: string;
    };
    format?: {
      type: SubjectTokenFormatType;
      subject_token_field_name?: string;
    };
  };
}

/**
 * Defines the Url-sourced and file-sourced external account clients mainly
 * used for K8s and Azure workloads.
 */
export class IdentityPoolClient extends BaseExternalAccountClient {
  private readonly file?: string;
  private readonly url?: string;
  private readonly headers?: {[key: string]: string};
  private readonly formatType: SubjectTokenFormatType;
  private readonly formatSubjectTokenFieldName?: string;

  /**
   * Instantiate an IdentityPoolClient instance using the provided JSON
   * object loaded from an external account credentials file.
   * An error is thrown if the credential is not a valid file-sourced or
   * url-sourced credential or a workforce pool user project is provided
   * with a non workforce audience.
   * @param options The external account options object typically loaded
   *   from the external account JSON credential file.
   * @param additionalOptions Optional additional behavior customization
   *   options. These currently customize expiration threshold time and
   *   whether to retry on 401/403 API request errors.
   */
  constructor(
    options: IdentityPoolClientOptions,
    additionalOptions?: RefreshOptions
  ) {
    super(options, additionalOptions);
    this.file = options.credential_source.file;
    this.url = options.credential_source.url;
    this.headers = options.credential_source.headers;
    if (!this.file && !this.url) {
      throw new Error('No valid Identity Pool "credential_source" provided');
    }
    // Text is the default format type.
    this.formatType = options.credential_source.format?.type || 'text';
    this.formatSubjectTokenFieldName =
      options.credential_source.format?.subject_token_field_name;
    if (this.formatType !== 'json' && this.formatType !== 'text') {
      throw new Error(`Invalid credential_source format "${this.formatType}"`);
    }
    if (this.formatType === 'json' && !this.formatSubjectTokenFieldName) {
      throw new Error(
        'Missing subject_token_field_name for JSON credential_source format'
      );
    }
  }

  /**
   * Triggered when a external subject token is needed to be exchanged for a GCP
   * access token via GCP STS endpoint.
   * This uses the `options.credential_source` object to figure out how
   * to retrieve the token using the current environment. In this case,
   * this either retrieves the local credential from a file location (k8s
   * workload) or by sending a GET request to a local metadata server (Azure
   * workloads).
   * @return A promise that resolves with the external subject token.
   */
  async retrieveSubjectToken(): Promise<string> {
    if (this.file) {
      return await this.getTokenFromFile(
        this.file!,
        this.formatType,
        this.formatSubjectTokenFieldName
      );
    }
    return await this.getTokenFromUrl(
      this.url!,
      this.formatType,
      this.formatSubjectTokenFieldName,
      this.headers
    );
  }

  /**
   * Looks up the external subject token in the file path provided and
   * resolves with that token.
   * @param file The file path where the external credential is located.
   * @param formatType The token file or URL response type (JSON or text).
   * @param formatSubjectTokenFieldName For JSON response types, this is the
   *   subject_token field name. For Azure, this is access_token. For text
   *   response types, this is ignored.
   * @return A promise that resolves with the external subject token.
   */
  private async getTokenFromFile(
    filePath: string,
    formatType: SubjectTokenFormatType,
    formatSubjectTokenFieldName?: string
  ): Promise<string> {
    // Make sure there is a file at the path. lstatSync will throw if there is
    // nothing there.
    try {
      // Resolve path to actual file in case of symlink. Expect a thrown error
      // if not resolvable.
      filePath = await realpath(filePath);

      if (!(await lstat(filePath)).isFile()) {
        throw new Error();
      }
    } catch (err) {
      if (err instanceof Error) {
        err.message = `The file at ${filePath} does not exist, or it is not a file. ${err.message}`;
      }

      throw err;
    }

    let subjectToken: string | undefined;
    const rawText = await readFile(filePath, {encoding: 'utf8'});
    if (formatType === 'text') {
      subjectToken = rawText;
    } else if (formatType === 'json' && formatSubjectTokenFieldName) {
      const json = JSON.parse(rawText) as SubjectTokenJsonResponse;
      subjectToken = json[formatSubjectTokenFieldName];
    }
    if (!subjectToken) {
      throw new Error(
        'Unable to parse the subject_token from the credential_source file'
      );
    }
    return subjectToken;
  }

  /**
   * Sends a GET request to the URL provided and resolves with the returned
   * external subject token.
   * @param url The URL to call to retrieve the subject token. This is typically
   *   a local metadata server.
   * @param formatType The token file or URL response type (JSON or text).
   * @param formatSubjectTokenFieldName For JSON response types, this is the
   *   subject_token field name. For Azure, this is access_token. For text
   *   response types, this is ignored.
   * @param headers The optional additional headers to send with the request to
   *   the metadata server url.
   * @return A promise that resolves with the external subject token.
   */
  private async getTokenFromUrl(
    url: string,
    formatType: SubjectTokenFormatType,
    formatSubjectTokenFieldName?: string,
    headers?: {[key: string]: string}
  ): Promise<string> {
    const opts: GaxiosOptions = {
      url,
      method: 'GET',
      headers,
      responseType: formatType,
    };
    let subjectToken: string | undefined;
    if (formatType === 'text') {
      const response = await this.transporter.request<string>(opts);
      subjectToken = response.data;
    } else if (formatType === 'json' && formatSubjectTokenFieldName) {
      const response = await this.transporter.request<SubjectTokenJsonResponse>(
        opts
      );
      subjectToken = response.data[formatSubjectTokenFieldName];
    }
    if (!subjectToken) {
      throw new Error(
        'Unable to parse the subject_token from the credential_source URL'
      );
    }
    return subjectToken;
  }
}
