/**
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {AxiosError} from 'axios';
import {exec} from 'child_process';
import * as fs from 'fs';
import * as gcpMetadata from 'gcp-metadata';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import * as stream from 'stream';
import * as util from 'util';

import {DefaultTransporter, Transporter} from '../transporters';

import {Compute} from './computeclient';
import {JWTInput} from './credentials';
import {GCPEnv, getEnv} from './envDetect';
import {JWTAccess} from './jwtaccess';
import {JWT, JWTOptions} from './jwtclient';
import {GetAccessTokenResponse, OAuth2Client, RefreshOptions, RequestMetadataResponse} from './oauth2client';
import {UserRefreshClient, UserRefreshClientOptions} from './refreshclient';

export interface ProjectIdCallback {
  (err?: Error|null, projectId?: string): void;
}

export interface CredentialCallback {
  (err: Error|null, result?: UserRefreshClient|JWT): void;
}

export interface ADCCallback {
  (err: Error|null, client?: OAuth2Client, projectId?: string): void;
}

export interface ADCResponse {
  client: OAuth2Client;
  projectId?: string;
}

export interface CredentialBody {
  client_email?: string;
  private_key?: string;
}

interface CredentialResult {
  default: {email: string;};
}

export interface GoogleAuthOptions {
  /**
   * Path to a .json, .pem, or .p12 key file
   */
  keyFilename?: string;

  /**
   * Path to a .json, .pem, or .p12 key file
   */
  keyFile?: string;

  /**
   * Object containing client_email and private_key properties
   */
  credentials?: CredentialBody;

  /**
   * Required scopes for the desired API request
   */
  scopes?: string|string[];

  /**
   * Your project ID.
   */
  projectId?: string;
}

export class GoogleAuth {
  transporter?: Transporter;

  /**
   * Caches a value indicating whether the auth layer is running on Google
   * Compute Engine.
   * @private
   */
  private checkIsGCE?: boolean = undefined;

  // Note:  this properly is only public to satisify unit tests.
  // https://github.com/Microsoft/TypeScript/issues/5228
  get isGCE() {
    return this.checkIsGCE;
  }

  private _getDefaultProjectIdPromise?: Promise<string>;
  private _cachedProjectId?: string;

  // To save the contents of the JSON credential file
  jsonContent: JWTInput|undefined;

  cachedClient: JWT|UserRefreshClient|Compute|undefined;

  private keyFilename?: string;
  private scopes?: string|string[];

  /**
   * Export DefaultTransporter as a static property of the class.
   */
  static DefaultTransporter = DefaultTransporter;

  constructor(opts?: GoogleAuthOptions) {
    opts = opts || {};
    this._cachedProjectId = opts.projectId;
    this.keyFilename = opts.keyFilename || opts.keyFile;
    this.scopes = opts.scopes;
    this.jsonContent = opts.credentials;
  }

  /**
   * Obtains the default project ID for the application.
   * @param callback Optional callback
   * @returns Promise that resolves with project Id (if used without callback)
   */
  getDefaultProjectId(): Promise<string>;
  getDefaultProjectId(callback: ProjectIdCallback): void;
  getDefaultProjectId(callback?: ProjectIdCallback): Promise<string>|void {
    if (callback) {
      this.getDefaultProjectIdAsync()
          .then(r => callback(null, r))
          .catch(callback);
    } else {
      return this.getDefaultProjectIdAsync();
    }
  }

  private getDefaultProjectIdAsync(): Promise<string> {
    if (this._cachedProjectId) {
      return Promise.resolve(this._cachedProjectId);
    }

    // In implicit case, supports three environments. In order of precedence,
    // the implicit environments are:
    // - GCLOUD_PROJECT or GOOGLE_CLOUD_PROJECT environment variable
    // - GOOGLE_APPLICATION_CREDENTIALS JSON file
    // - Cloud SDK: `gcloud config config-helper --format json`
    // - GCE project ID from metadata server)
    if (!this._getDefaultProjectIdPromise) {
      this._getDefaultProjectIdPromise =
          new Promise(async (resolve, reject) => {
            try {
              const projectId = this.getProductionProjectId() ||
                  await this.getFileProjectId() ||
                  await this.getDefaultServiceProjectId() ||
                  await this.getGCEProjectId();
              this._cachedProjectId = projectId;
              resolve(projectId);
            } catch (e) {
              reject(e);
            }
          });
    }
    return this._getDefaultProjectIdPromise;
  }

  /**
   * Obtains the default service-level credentials for the application.
   * @param callback Optional callback.
   * @returns Promise that resolves with the ADCResponse (if no callback was
   * passed).
   */
  getApplicationDefault(): Promise<ADCResponse>;
  getApplicationDefault(callback: ADCCallback): void;
  getApplicationDefault(options: RefreshOptions): Promise<ADCResponse>;
  getApplicationDefault(options: RefreshOptions, callback: ADCCallback): void;
  getApplicationDefault(
      optionsOrCallback: ADCCallback|RefreshOptions = {},
      callback?: ADCCallback): void|Promise<ADCResponse> {
    let options: RefreshOptions|undefined;
    if (typeof optionsOrCallback === 'function') {
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
    }
    if (callback) {
      this.getApplicationDefaultAsync(options)
          .then(r => callback!(null, r.client, r.projectId))
          .catch(callback);
    } else {
      return this.getApplicationDefaultAsync(options);
    }
  }


  private async getApplicationDefaultAsync(options?: RefreshOptions):
      Promise<ADCResponse> {
    // If we've already got a cached credential, just return it.
    if (this.cachedClient) {
      return {
        client: this.cachedClient as JWT | UserRefreshClient,
        projectId: await this.getDefaultProjectIdAsync()
      };
    }

    let client: JWT|UserRefreshClient|undefined;
    let projectId: string;
    // Check for the existence of a local environment variable pointing to the
    // location of the credential file. This is typically used in local
    // developer scenarios.
    client = await this._tryGetApplicationCredentialsFromEnvironmentVariable(
        options);
    if (client) {
      if (client instanceof JWT) {
        client.scopes = this.scopes;
      }
      this.cachedClient = client;
      projectId = await this.getDefaultProjectId();
      return {client, projectId};
    }

    // Look in the well-known credential file location.
    client = await this._tryGetApplicationCredentialsFromWellKnownFile(options);
    if (client) {
      if (client instanceof JWT) {
        client.scopes = this.scopes;
      }
      this.cachedClient = client;
      projectId = await this.getDefaultProjectId();
      return {client, projectId};
    }

    try {
      // Determine if we're running on GCE.
      const gce = await this._checkIsGCE();
      if (gce) {
        // For GCE, just return a default ComputeClient. It will take care of
        // the rest.
        this.cachedClient = new Compute(options);
        projectId = await this.getDefaultProjectId();
        return {projectId, client: this.cachedClient};
      } else {
        // We failed to find the default credentials. Bail out with an error.
        throw new Error(
            'Could not load the default credentials. Browse to https://developers.google.com/accounts/docs/application-default-credentials for more information.');
      }
    } catch (e) {
      throw new Error(
          'Unexpected error while acquiring application default credentials: ' +
          e.message);
    }
  }

  /**
   * Determines whether the auth layer is running on Google Compute Engine.
   * @returns A promise that resolves with the boolean.
   * @api private
   */
  async _checkIsGCE() {
    if (this.checkIsGCE === undefined) {
      this.checkIsGCE = await gcpMetadata.isAvailable();
    }
    return this.checkIsGCE;
  }

  /**
   * Attempts to load default credentials from the environment variable path..
   * @returns Promise that resolves with the OAuth2Client or undefined.
   * @api private
   */
  async _tryGetApplicationCredentialsFromEnvironmentVariable(
      options?: RefreshOptions): Promise<JWT|UserRefreshClient|undefined> {
    const credentialsPath = process.env['GOOGLE_APPLICATION_CREDENTIALS'];
    if (!credentialsPath || credentialsPath.length === 0) {
      return undefined;
    }
    try {
      return this._getApplicationCredentialsFromFilePath(
          credentialsPath, options);
    } catch (e) {
      throw this.createError(
          'Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable.',
          e);
    }
  }

  /**
   * Attempts to load default credentials from a well-known file location
   * @return Promise that resolves with the OAuth2Client or null.
   * @api private
   */
  async _tryGetApplicationCredentialsFromWellKnownFile(
      options?: RefreshOptions): Promise<JWT|UserRefreshClient|undefined> {
    // First, figure out the location of the file, depending upon the OS type.
    let location: string|undefined;
    if (this._isWindows()) {
      // Windows
      location = process.env['APPDATA'];
    } else {
      // Linux or Mac
      const home = process.env['HOME'];
      if (home) {
        location = this._pathJoin(home, '.config');
      }
    }
    // If we found the root path, expand it.
    if (location) {
      location = this._pathJoin(location, 'gcloud');
      location =
          this._pathJoin(location, 'application_default_credentials.json');
      location = this._mockWellKnownFilePath(location);
      // Check whether the file exists.
      if (!this._fileExists(location)) {
        location = undefined;
      }
    }
    // The file does not exist.
    if (!location) {
      return undefined;
    }
    // The file seems to exist. Try to use it.
    return this._getApplicationCredentialsFromFilePath(location, options);
  }

  /**
   * Attempts to load default credentials from a file at the given path..
   * @param filePath The path to the file to read.
   * @returns Promise that resolves with the OAuth2Client
   * @api private
   */
  async _getApplicationCredentialsFromFilePath(
      filePath: string,
      options: RefreshOptions = {}): Promise<JWT|UserRefreshClient> {
    // Make sure the path looks like a string.
    if (!filePath || filePath.length === 0) {
      throw new Error('The file path is invalid.');
    }

    // Make sure there is a file at the path. lstatSync will throw if there is
    // nothing there.
    try {
      // Resolve path to actual file in case of symlink. Expect a thrown error
      // if not resolvable.
      filePath = fs.realpathSync(filePath);

      if (!fs.lstatSync(filePath).isFile()) {
        throw new Error();
      }
    } catch (err) {
      throw this.createError(
          util.format(
              'The file at %s does not exist, or it is not a file.', filePath),
          err);
    }

    // Now open a read stream on the file, and parse it.
    try {
      const readStream = this._createReadStream(filePath);
      return this.fromStream(readStream, options);
    } catch (err) {
      throw this.createError(
          util.format('Unable to read the file at %s.', filePath), err);
    }
  }

  /**
   * Create a credentials instance using the given input options.
   * @param json The input object.
   * @returns JWT or UserRefresh Client with data
   */
  fromJSON(json: JWTInput, options?: RefreshOptions): JWT|UserRefreshClient {
    let client: UserRefreshClient|JWT;
    if (!json) {
      throw new Error(
          'Must pass in a JSON object containing the Google auth settings.');
    }
    this.jsonContent = json;
    options = options || {};
    if (json.type === 'authorized_user') {
      client = new UserRefreshClient(options);
    } else {
      (options as JWTOptions).scopes = this.scopes;
      client = new JWT(options);
    }
    client.fromJSON(json);
    return client;
  }

  /**
   * Create a credentials instance using the given input stream.
   * @param inputStream The input stream.
   * @param callback Optional callback.
   */
  fromStream(inputStream: stream.Readable): Promise<JWT|UserRefreshClient>;
  fromStream(inputStream: stream.Readable, callback: CredentialCallback): void;
  fromStream(inputStream: stream.Readable, options: RefreshOptions):
      Promise<JWT|UserRefreshClient>;
  fromStream(
      inputStream: stream.Readable, options: RefreshOptions,
      callback: CredentialCallback): void;
  fromStream(
      inputStream: stream.Readable,
      optionsOrCallback: RefreshOptions|CredentialCallback = {},
      callback?: CredentialCallback): Promise<JWT|UserRefreshClient>|void {
    let options: RefreshOptions = {};
    if (typeof optionsOrCallback === 'function') {
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
    }
    if (callback) {
      this.fromStreamAsync(inputStream, options)
          .then(r => callback!(null, r))
          .catch(callback);
    } else {
      return this.fromStreamAsync(inputStream, options);
    }
  }

  private fromStreamAsync(
      inputStream: stream.Readable,
      options?: RefreshOptions): Promise<JWT|UserRefreshClient> {
    return new Promise((resolve, reject) => {
      if (!inputStream) {
        throw new Error(
            'Must pass in a stream containing the Google auth settings.');
      }
      let s = '';
      inputStream.setEncoding('utf8');
      inputStream.on('data', (chunk) => {
        s += chunk;
      });
      inputStream.on('end', () => {
        try {
          const data = JSON.parse(s);
          const r = this.fromJSON(data, options);
          return resolve(r);
        } catch (err) {
          return reject(err);
        }
      });
    });
  }

  /**
   * Create a credentials instance using the given API key string.
   * @param apiKey The API key string
   * @param options An optional options object.
   * @returns A JWT loaded from the key
   */
  fromAPIKey(apiKey: string, options?: RefreshOptions): JWT {
    options = options || {};
    const client = new JWT(options);
    client.fromAPIKey(apiKey);
    return client;
  }

  /**
   * Determines whether the current operating system is Windows.
   * @api private
   */
  private _isWindows() {
    const sys = this._osPlatform();
    if (sys && sys.length >= 3) {
      if (sys.substring(0, 3).toLowerCase() === 'win') {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates a file stream. Allows mocking.
   * @api private
   */
  _createReadStream(filePath: string) {
    return fs.createReadStream(filePath);
  }

  /**
   * Gets the current operating system platform. Allows mocking.
   * @api private
   */
  _osPlatform() {
    return os.platform();
  }

  /**
   * Determines whether a file exists. Allows mocking.
   * @api private
   */
  _fileExists(filePath: string) {
    return fs.existsSync(filePath);
  }

  /**
   * Joins two parts of a path. Allows mocking.
   * @api private
   */
  _pathJoin(item1: string, item2: string) {
    return path.join(item1, item2);
  }

  /**
   * Allows mocking of the path to a well-known file.
   * @api private
   */
  _mockWellKnownFilePath(filePath: string) {
    return filePath;
  }

  // Creates an Error containing the given message, and includes the message
  // from the optional err passed in.
  private createError(message: string, err: Error) {
    let s = message || '';
    if (err) {
      const errorMessage = String(err);
      if (errorMessage && errorMessage.length > 0) {
        if (s.length > 0) {
          s += ' ';
        }
        s += errorMessage;
      }
    }
    return Error(s);
  }

  /**
   * Run the Google Cloud SDK command that prints the default project ID
   */
  private async getDefaultServiceProjectId(): Promise<string|null> {
    return new Promise<string|null>(resolve => {
      exec(
          'gcloud config config-helper --format json',
          (err, stdout, stderr) => {
            if (!err && stdout) {
              try {
                const projectId =
                    JSON.parse(stdout).configuration.properties.core.project;
                resolve(projectId);
                return;
              } catch (e) {
                // ignore errors
              }
            }
            resolve(null);
          });
    });
  }

  /**
   * Loads the project id from environment variables.
   * @api private
   */
  private getProductionProjectId() {
    return process.env['GCLOUD_PROJECT'] || process.env['GOOGLE_CLOUD_PROJECT'];
  }

  /**
   * Loads the project id from the GOOGLE_APPLICATION_CREDENTIALS json file.
   * @api private
   */
  private async getFileProjectId(): Promise<string|undefined> {
    if (this.cachedClient) {
      // Try to read the project ID from the cached credentials file
      return this.cachedClient.projectId;
    }
    // Try to load a credentials file and read its project ID
    const r = await this._tryGetApplicationCredentialsFromEnvironmentVariable();
    return r ? r.projectId : undefined;
  }

  /**
   * Gets the Compute Engine project ID if it can be inferred.
   */
  private async getGCEProjectId() {
    try {
      const r = await gcpMetadata.project('project-id');
      return r.data;
    } catch (e) {
      // Ignore any errors
      return undefined;
    }
  }

  /**
   * The callback function handles a credential object that contains the
   * client_email and private_key (if exists).
   * getCredentials checks for these values from the user JSON at first.
   * If it doesn't exist, and the environment is on GCE, it gets the
   * client_email from the cloud metadata server.
   * @param callback Callback that handles the credential object that contains
   * a client_email and optional private key, or the error.
   * returned
   */
  getCredentials(): Promise<CredentialBody>;
  getCredentials(
      callback: (err: Error|null, credentials?: CredentialBody) => void): void;
  getCredentials(
      callback?: (err: Error|null, credentials?: CredentialBody) => void):
      void|Promise<CredentialBody> {
    if (callback) {
      this.getCredentialsAsync().then(r => callback(null, r)).catch(callback);
    } else {
      return this.getCredentialsAsync();
    }
  }

  private async getCredentialsAsync(): Promise<CredentialBody> {
    if (this.jsonContent) {
      const credential: CredentialBody = {
        client_email: this.jsonContent.client_email,
        private_key: this.jsonContent.private_key
      };
      return credential;
    }

    const isGCE = await this._checkIsGCE();
    if (!isGCE) {
      throw new Error('Unknown error.');
    }

    // For GCE, return the service account details from the metadata server
    const {data} = await gcpMetadata.instance(
        {property: 'service-accounts', params: {recursive: true}});

    if (!data || !data.default || !data.default.email) {
      throw new Error('Failure from metadata server.');
    }

    return {client_email: data.default.email};
  }

  /**
   * Automatically obtain a client based on the provided configuration.  If no
   * options were passed, use Application Default Credentials.
   */
  async getClient(options?: GoogleAuthOptions) {
    if (options) {
      this.keyFilename =
          options.keyFilename || options.keyFile || this.keyFilename;
      this.scopes = options.scopes || this.scopes;
      this.jsonContent = options.credentials || this.jsonContent;
    }
    if (!this.cachedClient) {
      if (this.keyFilename) {
        const filePath = path.resolve(this.keyFilename);
        const stream = fs.createReadStream(filePath);
        this.cachedClient = await this.fromStreamAsync(stream);
      } else if (this.jsonContent) {
        this.cachedClient = await this.fromJSON(this.jsonContent);
      } else {
        await this.getApplicationDefaultAsync();
      }
    }
    return this.cachedClient!;
  }

  /**
   * Automatically obtain application default credentials, and return
   * an access token for making requests.
   */
  async getAccessToken() {
    const client = await this.getClient();
    return (await client.getAccessToken()).token;
  }

  /**
   * Obtain the HTTP headers that will provide authorization for a given
   * request.
   */
  async getRequestHeaders(url?: string) {
    const client = await this.getClient();
    return (await client.getRequestMetadata(url)).headers;
  }

  /**
   * Obtain credentials for a request, then attach the appropriate headers to
   * the request options.
   * @param opts Axios or Request options on which to attach the headers
   */
  async authorizeRequest(
      opts: {url?: string, uri?: string, headers?: http.IncomingHttpHeaders}) {
    opts = opts || {};
    const url = opts.url || opts.uri;
    const client = await this.getClient();
    const {headers} = await client.getRequestMetadata(url);
    opts.headers = Object.assign(opts.headers || {}, headers);
    return opts;
  }

  /**
   * Determine the compute environment in which the code is running.
   */
  getEnv(): Promise<GCPEnv> {
    return getEnv();
  }
}
