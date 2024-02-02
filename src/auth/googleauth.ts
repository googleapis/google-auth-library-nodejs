// Copyright 2019 Google LLC
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

import {exec} from 'child_process';
import * as fs from 'fs';
import {GaxiosError, GaxiosOptions, GaxiosResponse} from 'gaxios';
import * as gcpMetadata from 'gcp-metadata';
import * as os from 'os';
import * as path from 'path';
import * as stream from 'stream';

import {Crypto, createCrypto} from '../crypto/crypto';
import {DefaultTransporter, Transporter} from '../transporters';

import {Compute, ComputeOptions} from './computeclient';
import {CredentialBody, ImpersonatedJWTInput, JWTInput} from './credentials';
import {IdTokenClient} from './idtokenclient';
import {GCPEnv, getEnv} from './envDetect';
import {JWT, JWTOptions} from './jwtclient';
import {Headers, OAuth2ClientOptions} from './oauth2client';
import {
  UserRefreshClient,
  UserRefreshClientOptions,
  USER_REFRESH_ACCOUNT_TYPE,
} from './refreshclient';
import {
  Impersonated,
  ImpersonatedOptions,
  IMPERSONATED_ACCOUNT_TYPE,
} from './impersonated';
import {
  ExternalAccountClient,
  ExternalAccountClientOptions,
} from './externalclient';
import {
  EXTERNAL_ACCOUNT_TYPE,
  BaseExternalAccountClient,
} from './baseexternalclient';
import {AuthClient, AuthClientOptions, DEFAULT_UNIVERSE} from './authclient';
import {
  EXTERNAL_ACCOUNT_AUTHORIZED_USER_TYPE,
  ExternalAccountAuthorizedUserClient,
  ExternalAccountAuthorizedUserClientOptions,
} from './externalAccountAuthorizedUserClient';
import {originalOrCamelOptions} from '../util';

/**
 * Defines all types of explicit clients that are determined via ADC JSON
 * config file.
 */
export type JSONClient =
  | JWT
  | UserRefreshClient
  | BaseExternalAccountClient
  | ExternalAccountAuthorizedUserClient
  | Impersonated;

export interface ProjectIdCallback {
  (err?: Error | null, projectId?: string | null): void;
}

export interface CredentialCallback {
  (err: Error | null, result?: JSONClient): void;
}

export interface ADCCallback {
  (err: Error | null, credential?: AuthClient, projectId?: string | null): void;
}

export interface ADCResponse {
  credential: AuthClient;
  projectId: string | null;
}

export interface GoogleAuthOptions<T extends AuthClient = JSONClient> {
  /**
   * An `AuthClient` to use
   */
  authClient?: T;
  /**
   * Path to a .json, .pem, or .p12 key file
   */
  keyFilename?: string;

  /**
   * Path to a .json, .pem, or .p12 key file
   */
  keyFile?: string;

  /**
   * Object containing client_email and private_key properties, or the
   * external account client options.
   */
  credentials?: JWTInput | ExternalAccountClientOptions;

  /**
   * Options object passed to the constructor of the client
   */
  clientOptions?:
    | JWTOptions
    | OAuth2ClientOptions
    | UserRefreshClientOptions
    | ImpersonatedOptions;

  /**
   * Required scopes for the desired API request
   */
  scopes?: string | string[];

  /**
   * Your project ID.
   */
  projectId?: string;

  /**
   * The default service domain for a given Cloud universe.
   *
   * This is an ergonomic equivalent to {@link clientOptions}'s `universeDomain`
   * property and will be set for all generated {@link AuthClient}s.
   */
  universeDomain?: string;
}

export const CLOUD_SDK_CLIENT_ID =
  '764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com';

const GoogleAuthExceptionMessages = {
  NO_PROJECT_ID_FOUND:
    'Unable to detect a Project Id in the current environment. \n' +
    'To learn more about authentication and Google APIs, visit: \n' +
    'https://cloud.google.com/docs/authentication/getting-started',
  NO_CREDENTIALS_FOUND:
    'Unable to find credentials in current environment. \n' +
    'To learn more about authentication and Google APIs, visit: \n' +
    'https://cloud.google.com/docs/authentication/getting-started',
  NO_UNIVERSE_DOMAIN_FOUND:
    'Unable to detect a Universe Domain in the current environment.\n' +
    'To learn more about Universe Domain retrieval, visit: \n' +
    'https://cloud.google.com/compute/docs/metadata/predefined-metadata-keys',
} as const;

export class GoogleAuth<T extends AuthClient = JSONClient> {
  transporter?: Transporter;

  /**
   * Caches a value indicating whether the auth layer is running on Google
   * Compute Engine.
   * @private
   */
  private checkIsGCE?: boolean = undefined;
  useJWTAccessWithScope?: boolean;
  defaultServicePath?: string;

  // Note:  this properly is only public to satisify unit tests.
  // https://github.com/Microsoft/TypeScript/issues/5228
  get isGCE() {
    return this.checkIsGCE;
  }

  private _findProjectIdPromise?: Promise<string | null>;
  private _cachedProjectId?: string | null;

  // To save the contents of the JSON credential file
  jsonContent: JWTInput | ExternalAccountClientOptions | null = null;

  cachedCredential: JSONClient | Impersonated | Compute | T | null = null;

  /**
   * Scopes populated by the client library by default. We differentiate between
   * these and user defined scopes when deciding whether to use a self-signed JWT.
   */
  defaultScopes?: string | string[];
  private keyFilename?: string;
  private scopes?: string | string[];
  private clientOptions: AuthClientOptions = {};

  /**
   * Export DefaultTransporter as a static property of the class.
   */
  static DefaultTransporter = DefaultTransporter;

  /**
   * Configuration is resolved in the following order of precedence:
   * - {@link GoogleAuthOptions.credentials `credentials`}
   * - {@link GoogleAuthOptions.keyFilename `keyFilename`}
   * - {@link GoogleAuthOptions.keyFile `keyFile`}
   *
   * {@link GoogleAuthOptions.clientOptions `clientOptions`} are passed to the
   * {@link AuthClient `AuthClient`s}.
   *
   * @param opts
   */
  constructor(opts?: GoogleAuthOptions<T>) {
    opts = opts || {};

    this._cachedProjectId = opts.projectId || null;
    this.cachedCredential = opts.authClient || null;
    this.keyFilename = opts.keyFilename || opts.keyFile;
    this.scopes = opts.scopes;
    this.jsonContent = opts.credentials || null;
    this.clientOptions = opts.clientOptions || {};

    if (opts.universeDomain) {
      this.clientOptions.universeDomain = opts.universeDomain;
    }
  }

  // GAPIC client libraries should always use self-signed JWTs. The following
  // variables are set on the JWT client in order to indicate the type of library,
  // and sign the JWT with the correct audience and scopes (if not supplied).
  setGapicJWTValues(client: JWT) {
    client.defaultServicePath = this.defaultServicePath;
    client.useJWTAccessWithScope = this.useJWTAccessWithScope;
    client.defaultScopes = this.defaultScopes;
  }

  /**
   * Obtains the default project ID for the application.
   *
   * Retrieves in the following order of precedence:
   * - The `projectId` provided in this object's construction
   * - GCLOUD_PROJECT or GOOGLE_CLOUD_PROJECT environment variable
   * - GOOGLE_APPLICATION_CREDENTIALS JSON file
   * - Cloud SDK: `gcloud config config-helper --format json`
   * - GCE project ID from metadata server
   */
  getProjectId(): Promise<string>;
  getProjectId(callback: ProjectIdCallback): void;
  getProjectId(callback?: ProjectIdCallback): Promise<string | null> | void {
    if (callback) {
      this.getProjectIdAsync().then(r => callback(null, r), callback);
    } else {
      return this.getProjectIdAsync();
    }
  }

  /**
   * A temporary method for internal `getProjectId` usages where `null` is
   * acceptable. In a future major release, `getProjectId` should return `null`
   * (as the `Promise<string | null>` base signature describes) and this private
   * method should be removed.
   *
   * @returns Promise that resolves with project id (or `null`)
   */
  private async getProjectIdOptional(): Promise<string | null> {
    try {
      return await this.getProjectId();
    } catch (e) {
      if (
        e instanceof Error &&
        e.message === GoogleAuthExceptionMessages.NO_PROJECT_ID_FOUND
      ) {
        return null;
      } else {
        throw e;
      }
    }
  }

  /*
   * A private method for finding and caching a projectId.
   *
   * Supports environments in order of precedence:
   * - GCLOUD_PROJECT or GOOGLE_CLOUD_PROJECT environment variable
   * - GOOGLE_APPLICATION_CREDENTIALS JSON file
   * - Cloud SDK: `gcloud config config-helper --format json`
   * - GCE project ID from metadata server
   *
   * @returns projectId
   */
  private async findAndCacheProjectId(): Promise<string> {
    let projectId: string | null | undefined = null;

    projectId ||= await this.getProductionProjectId();
    projectId ||= await this.getFileProjectId();
    projectId ||= await this.getDefaultServiceProjectId();
    projectId ||= await this.getGCEProjectId();
    projectId ||= await this.getExternalAccountClientProjectId();

    if (projectId) {
      this._cachedProjectId = projectId;
      return projectId;
    } else {
      throw new Error(GoogleAuthExceptionMessages.NO_PROJECT_ID_FOUND);
    }
  }

  private async getProjectIdAsync(): Promise<string | null> {
    if (this._cachedProjectId) {
      return this._cachedProjectId;
    }

    if (!this._findProjectIdPromise) {
      this._findProjectIdPromise = this.findAndCacheProjectId();
    }
    return this._findProjectIdPromise;
  }

  /**
   * Retrieves a universe domain from the metadata server via
   * {@link gcpMetadata.universe}.
   *
   * @returns a universe domain
   */
  async getUniverseDomainFromMetadataServer(): Promise<string> {
    let universeDomain: string;

    try {
      universeDomain = await gcpMetadata.universe('universe_domain');
      universeDomain ||= DEFAULT_UNIVERSE;
    } catch (e) {
      if (e && (e as GaxiosError)?.response?.status === 404) {
        universeDomain = DEFAULT_UNIVERSE;
      } else {
        throw e;
      }
    }

    return universeDomain;
  }

  /**
   * Retrieves, caches, and returns the universe domain in the following order
   * of precedence:
   * - The universe domain in {@link GoogleAuth.clientOptions}
   * - An existing or ADC {@link AuthClient}'s universe domain
   * - {@link gcpMetadata.universe}, if {@link Compute} client
   *
   * @returns The universe domain
   */
  async getUniverseDomain(): Promise<string> {
    let universeDomain = originalOrCamelOptions(this.clientOptions).get(
      'universe_domain'
    );
    try {
      universeDomain ??= (await this.getClient()).universeDomain;
    } catch {
      // client or ADC is not available
      universeDomain ??= DEFAULT_UNIVERSE;
    }

    return universeDomain;
  }

  /**
   * @returns Any scopes (user-specified or default scopes specified by the
   *   client library) that need to be set on the current Auth client.
   */
  private getAnyScopes(): string | string[] | undefined {
    return this.scopes || this.defaultScopes;
  }

  /**
   * Obtains the default service-level credentials for the application.
   * @param callback Optional callback.
   * @returns Promise that resolves with the ADCResponse (if no callback was
   * passed).
   */
  getApplicationDefault(): Promise<ADCResponse>;
  getApplicationDefault(callback: ADCCallback): void;
  getApplicationDefault(options: AuthClientOptions): Promise<ADCResponse>;
  getApplicationDefault(
    options: AuthClientOptions,
    callback: ADCCallback
  ): void;
  getApplicationDefault(
    optionsOrCallback: ADCCallback | AuthClientOptions = {},
    callback?: ADCCallback
  ): void | Promise<ADCResponse> {
    let options: AuthClientOptions | undefined;
    if (typeof optionsOrCallback === 'function') {
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
    }
    if (callback) {
      this.getApplicationDefaultAsync(options).then(
        r => callback!(null, r.credential, r.projectId),
        callback
      );
    } else {
      return this.getApplicationDefaultAsync(options);
    }
  }

  private async getApplicationDefaultAsync(
    options: AuthClientOptions = {}
  ): Promise<ADCResponse> {
    // If we've already got a cached credential, return it.
    // This will also preserve one's configured quota project, in case they
    // set one directly on the credential previously.
    if (this.cachedCredential) {
      return await this.prepareAndCacheADC(this.cachedCredential);
    }

    // Since this is a 'new' ADC to cache we will use the environment variable
    // if it's available. We prefer this value over the value from ADC.
    const quotaProjectIdOverride = process.env['GOOGLE_CLOUD_QUOTA_PROJECT'];

    let credential: JSONClient | null;
    // Check for the existence of a local environment variable pointing to the
    // location of the credential file. This is typically used in local
    // developer scenarios.
    credential =
      await this._tryGetApplicationCredentialsFromEnvironmentVariable(options);
    if (credential) {
      if (credential instanceof JWT) {
        credential.scopes = this.scopes;
      } else if (credential instanceof BaseExternalAccountClient) {
        credential.scopes = this.getAnyScopes();
      }

      return await this.prepareAndCacheADC(credential, quotaProjectIdOverride);
    }

    // Look in the well-known credential file location.
    credential =
      await this._tryGetApplicationCredentialsFromWellKnownFile(options);
    if (credential) {
      if (credential instanceof JWT) {
        credential.scopes = this.scopes;
      } else if (credential instanceof BaseExternalAccountClient) {
        credential.scopes = this.getAnyScopes();
      }
      return await this.prepareAndCacheADC(credential, quotaProjectIdOverride);
    }

    // Determine if we're running on GCE.
    if (await this._checkIsGCE()) {
      // set universe domain for Compute client
      if (!originalOrCamelOptions(options).get('universe_domain')) {
        options.universeDomain =
          await this.getUniverseDomainFromMetadataServer();
      }

      (options as ComputeOptions).scopes = this.getAnyScopes();
      return await this.prepareAndCacheADC(
        new Compute(options),
        quotaProjectIdOverride
      );
    }

    throw new Error(
      'Could not load the default credentials. Browse to https://cloud.google.com/docs/authentication/getting-started for more information.'
    );
  }

  private async prepareAndCacheADC(
    credential: JSONClient | Impersonated | Compute | T,
    quotaProjectIdOverride?: string
  ): Promise<ADCResponse> {
    const projectId = await this.getProjectIdOptional();

    if (quotaProjectIdOverride) {
      credential.quotaProjectId = quotaProjectIdOverride;
    }

    this.cachedCredential = credential;

    return {credential, projectId};
  }

  /**
   * Determines whether the auth layer is running on Google Compute Engine.
   * Checks for GCP Residency, then fallback to checking if metadata server
   * is available.
   *
   * @returns A promise that resolves with the boolean.
   * @api private
   */
  async _checkIsGCE() {
    if (this.checkIsGCE === undefined) {
      this.checkIsGCE =
        gcpMetadata.getGCPResidency() || (await gcpMetadata.isAvailable());
    }

    return this.checkIsGCE;
  }

  /**
   * Attempts to load default credentials from the environment variable path..
   * @returns Promise that resolves with the OAuth2Client or null.
   * @api private
   */
  async _tryGetApplicationCredentialsFromEnvironmentVariable(
    options?: AuthClientOptions
  ): Promise<JSONClient | null> {
    const credentialsPath =
      process.env['GOOGLE_APPLICATION_CREDENTIALS'] ||
      process.env['google_application_credentials'];
    if (!credentialsPath || credentialsPath.length === 0) {
      return null;
    }
    try {
      return this._getApplicationCredentialsFromFilePath(
        credentialsPath,
        options
      );
    } catch (e) {
      if (e instanceof Error) {
        e.message = `Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS environment variable: ${e.message}`;
      }

      throw e;
    }
  }

  /**
   * Attempts to load default credentials from a well-known file location
   * @return Promise that resolves with the OAuth2Client or null.
   * @api private
   */
  async _tryGetApplicationCredentialsFromWellKnownFile(
    options?: AuthClientOptions
  ): Promise<JSONClient | null> {
    // First, figure out the location of the file, depending upon the OS type.
    let location = null;
    if (this._isWindows()) {
      // Windows
      location = process.env['APPDATA'];
    } else {
      // Linux or Mac
      const home = process.env['HOME'];
      if (home) {
        location = path.join(home, '.config');
      }
    }
    // If we found the root path, expand it.
    if (location) {
      location = path.join(
        location,
        'gcloud',
        'application_default_credentials.json'
      );
      if (!fs.existsSync(location)) {
        location = null;
      }
    }
    // The file does not exist.
    if (!location) {
      return null;
    }
    // The file seems to exist. Try to use it.
    const client = await this._getApplicationCredentialsFromFilePath(
      location,
      options
    );
    return client;
  }

  /**
   * Attempts to load default credentials from a file at the given path..
   * @param filePath The path to the file to read.
   * @returns Promise that resolves with the OAuth2Client
   * @api private
   */
  async _getApplicationCredentialsFromFilePath(
    filePath: string,
    options: AuthClientOptions = {}
  ): Promise<JSONClient> {
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
      if (err instanceof Error) {
        err.message = `The file at ${filePath} does not exist, or it is not a file. ${err.message}`;
      }

      throw err;
    }

    // Now open a read stream on the file, and parse it.
    const readStream = fs.createReadStream(filePath);
    return this.fromStream(readStream, options);
  }

  /**
   * Create a credentials instance using a given impersonated input options.
   * @param json The impersonated input object.
   * @returns JWT or UserRefresh Client with data
   */
  fromImpersonatedJSON(json: ImpersonatedJWTInput): Impersonated {
    if (!json) {
      throw new Error(
        'Must pass in a JSON object containing an  impersonated refresh token'
      );
    }
    if (json.type !== IMPERSONATED_ACCOUNT_TYPE) {
      throw new Error(
        `The incoming JSON object does not have the "${IMPERSONATED_ACCOUNT_TYPE}" type`
      );
    }
    if (!json.source_credentials) {
      throw new Error(
        'The incoming JSON object does not contain a source_credentials field'
      );
    }
    if (!json.service_account_impersonation_url) {
      throw new Error(
        'The incoming JSON object does not contain a service_account_impersonation_url field'
      );
    }

    // Create source client for impersonation
    const sourceClient = new UserRefreshClient();
    sourceClient.fromJSON(json.source_credentials);

    if (json.service_account_impersonation_url?.length > 256) {
      /**
       * Prevents DOS attacks.
       * @see {@link https://github.com/googleapis/google-auth-library-nodejs/security/code-scanning/85}
       **/
      throw new RangeError(
        `Target principal is too long: ${json.service_account_impersonation_url}`
      );
    }

    // Extreact service account from service_account_impersonation_url
    const targetPrincipal = /(?<target>[^/]+):generateAccessToken$/.exec(
      json.service_account_impersonation_url
    )?.groups?.target;

    if (!targetPrincipal) {
      throw new RangeError(
        `Cannot extract target principal from ${json.service_account_impersonation_url}`
      );
    }

    const targetScopes = this.getAnyScopes() ?? [];

    const client = new Impersonated({
      ...json,
      delegates: json.delegates ?? [],
      sourceClient: sourceClient,
      targetPrincipal: targetPrincipal,
      targetScopes: Array.isArray(targetScopes) ? targetScopes : [targetScopes],
    });
    return client;
  }

  /**
   * Create a credentials instance using the given input options.
   * @param json The input object.
   * @param options The JWT or UserRefresh options for the client
   * @returns JWT or UserRefresh Client with data
   */
  fromJSON(
    json: JWTInput | ImpersonatedJWTInput,
    options: AuthClientOptions = {}
  ): JSONClient {
    let client: JSONClient;

    // user's preferred universe domain
    const preferredUniverseDomain =
      originalOrCamelOptions(options).get('universe_domain');

    if (json.type === USER_REFRESH_ACCOUNT_TYPE) {
      client = new UserRefreshClient(options);
      client.fromJSON(json);
    } else if (json.type === IMPERSONATED_ACCOUNT_TYPE) {
      client = this.fromImpersonatedJSON(json as ImpersonatedJWTInput);
    } else if (json.type === EXTERNAL_ACCOUNT_TYPE) {
      client = ExternalAccountClient.fromJSON(
        json as ExternalAccountClientOptions,
        options
      )!;
      client.scopes = this.getAnyScopes();
    } else if (json.type === EXTERNAL_ACCOUNT_AUTHORIZED_USER_TYPE) {
      client = new ExternalAccountAuthorizedUserClient(
        json as ExternalAccountAuthorizedUserClientOptions,
        options
      );
    } else {
      (options as JWTOptions).scopes = this.scopes;
      client = new JWT(options);
      this.setGapicJWTValues(client);
      client.fromJSON(json);
    }

    if (preferredUniverseDomain) {
      client.universeDomain = preferredUniverseDomain;
    }

    return client;
  }

  /**
   * Return a JWT or UserRefreshClient from JavaScript object, caching both the
   * object used to instantiate and the client.
   * @param json The input object.
   * @param options The JWT or UserRefresh options for the client
   * @returns JWT or UserRefresh Client with data
   */
  private _cacheClientFromJSON(
    json: JWTInput | ImpersonatedJWTInput,
    options?: AuthClientOptions
  ): JSONClient {
    const client = this.fromJSON(json, options);

    // cache both raw data used to instantiate client and client itself.
    this.jsonContent = json;
    this.cachedCredential = client;
    return client;
  }

  /**
   * Create a credentials instance using the given input stream.
   * @param inputStream The input stream.
   * @param callback Optional callback.
   */
  fromStream(inputStream: stream.Readable): Promise<JSONClient>;
  fromStream(inputStream: stream.Readable, callback: CredentialCallback): void;
  fromStream(
    inputStream: stream.Readable,
    options: AuthClientOptions
  ): Promise<JSONClient>;
  fromStream(
    inputStream: stream.Readable,
    options: AuthClientOptions,
    callback: CredentialCallback
  ): void;
  fromStream(
    inputStream: stream.Readable,
    optionsOrCallback: AuthClientOptions | CredentialCallback = {},
    callback?: CredentialCallback
  ): Promise<JSONClient> | void {
    let options: AuthClientOptions = {};
    if (typeof optionsOrCallback === 'function') {
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback;
    }
    if (callback) {
      this.fromStreamAsync(inputStream, options).then(
        r => callback!(null, r),
        callback
      );
    } else {
      return this.fromStreamAsync(inputStream, options);
    }
  }

  private fromStreamAsync(
    inputStream: stream.Readable,
    options?: AuthClientOptions
  ): Promise<JSONClient> {
    return new Promise((resolve, reject) => {
      if (!inputStream) {
        throw new Error(
          'Must pass in a stream containing the Google auth settings.'
        );
      }
      let s = '';
      inputStream
        .setEncoding('utf8')
        .on('error', reject)
        .on('data', chunk => (s += chunk))
        .on('end', () => {
          try {
            try {
              const data = JSON.parse(s);
              const r = this._cacheClientFromJSON(data, options);
              return resolve(r);
            } catch (err) {
              // If we failed parsing this.keyFileName, assume that it
              // is a PEM or p12 certificate:
              if (!this.keyFilename) throw err;
              const client = new JWT({
                ...this.clientOptions,
                keyFile: this.keyFilename,
              });
              this.cachedCredential = client;
              this.setGapicJWTValues(client);
              return resolve(client);
            }
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
  fromAPIKey(apiKey: string, options?: AuthClientOptions): JWT {
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
    const sys = os.platform();
    if (sys && sys.length >= 3) {
      if (sys.substring(0, 3).toLowerCase() === 'win') {
        return true;
      }
    }
    return false;
  }

  /**
   * Run the Google Cloud SDK command that prints the default project ID
   */
  private async getDefaultServiceProjectId(): Promise<string | null> {
    return new Promise<string | null>(resolve => {
      exec('gcloud config config-helper --format json', (err, stdout) => {
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
    return (
      process.env['GCLOUD_PROJECT'] ||
      process.env['GOOGLE_CLOUD_PROJECT'] ||
      process.env['gcloud_project'] ||
      process.env['google_cloud_project']
    );
  }

  /**
   * Loads the project id from the GOOGLE_APPLICATION_CREDENTIALS json file.
   * @api private
   */
  private async getFileProjectId(): Promise<string | undefined | null> {
    if (this.cachedCredential) {
      // Try to read the project ID from the cached credentials file
      return this.cachedCredential.projectId;
    }

    // Ensure the projectId is loaded from the keyFile if available.
    if (this.keyFilename) {
      const creds = await this.getClient();

      if (creds && creds.projectId) {
        return creds.projectId;
      }
    }

    // Try to load a credentials file and read its project ID
    const r = await this._tryGetApplicationCredentialsFromEnvironmentVariable();
    if (r) {
      return r.projectId;
    } else {
      return null;
    }
  }

  /**
   * Gets the project ID from external account client if available.
   */
  private async getExternalAccountClientProjectId(): Promise<string | null> {
    if (!this.jsonContent || this.jsonContent.type !== EXTERNAL_ACCOUNT_TYPE) {
      return null;
    }
    const creds = await this.getClient();
    // Do not suppress the underlying error, as the error could contain helpful
    // information for debugging and fixing. This is especially true for
    // external account creds as in order to get the project ID, the following
    // operations have to succeed:
    // 1. Valid credentials file should be supplied.
    // 2. Ability to retrieve access tokens from STS token exchange API.
    // 3. Ability to exchange for service account impersonated credentials (if
    //    enabled).
    // 4. Ability to get project info using the access token from step 2 or 3.
    // Without surfacing the error, it is harder for developers to determine
    // which step went wrong.
    return await (creds as BaseExternalAccountClient).getProjectId();
  }

  /**
   * Gets the Compute Engine project ID if it can be inferred.
   */
  private async getGCEProjectId() {
    try {
      const r = await gcpMetadata.project('project-id');
      return r;
    } catch (e) {
      // Ignore any errors
      return null;
    }
  }

  /**
   * The callback function handles a credential object that contains the
   * client_email and private_key (if exists).
   * getCredentials first checks if the client is using an external account and
   * uses the service account email in place of client_email.
   * If that doesn't exist, it checks for these values from the user JSON.
   * If the user JSON doesn't exist, and the environment is on GCE, it gets the
   * client_email from the cloud metadata server.
   * @param callback Callback that handles the credential object that contains
   * a client_email and optional private key, or the error.
   * returned
   */
  getCredentials(): Promise<CredentialBody>;
  getCredentials(
    callback: (err: Error | null, credentials?: CredentialBody) => void
  ): void;
  getCredentials(
    callback?: (err: Error | null, credentials?: CredentialBody) => void
  ): void | Promise<CredentialBody> {
    if (callback) {
      this.getCredentialsAsync().then(r => callback(null, r), callback);
    } else {
      return this.getCredentialsAsync();
    }
  }

  private async getCredentialsAsync(): Promise<CredentialBody> {
    const client = await this.getClient();

    if (client instanceof Impersonated) {
      return {client_email: client.getTargetPrincipal()};
    }

    if (client instanceof BaseExternalAccountClient) {
      const serviceAccountEmail = client.getServiceAccountEmail();
      if (serviceAccountEmail) {
        return {
          client_email: serviceAccountEmail,
          universe_domain: client.universeDomain,
        };
      }
    }

    if (this.jsonContent) {
      return {
        client_email: (this.jsonContent as JWTInput).client_email,
        private_key: (this.jsonContent as JWTInput).private_key,
        universe_domain: this.jsonContent.universe_domain,
      };
    }

    if (await this._checkIsGCE()) {
      const [client_email, universe_domain] = await Promise.all([
        gcpMetadata.instance('service-accounts/default/email'),
        this.getUniverseDomain(),
      ]);

      return {client_email, universe_domain};
    }

    throw new Error(GoogleAuthExceptionMessages.NO_CREDENTIALS_FOUND);
  }

  /**
   * Automatically obtain an {@link AuthClient `AuthClient`} based on the
   * provided configuration. If no options were passed, use Application
   * Default Credentials.
   */
  async getClient() {
    if (!this.cachedCredential) {
      if (this.jsonContent) {
        this._cacheClientFromJSON(this.jsonContent, this.clientOptions);
      } else if (this.keyFilename) {
        const filePath = path.resolve(this.keyFilename);
        const stream = fs.createReadStream(filePath);
        await this.fromStreamAsync(stream, this.clientOptions);
      } else {
        await this.getApplicationDefaultAsync(this.clientOptions);
      }
    }
    return this.cachedCredential!;
  }

  /**
   * Creates a client which will fetch an ID token for authorization.
   * @param targetAudience the audience for the fetched ID token.
   * @returns IdTokenClient for making HTTP calls authenticated with ID tokens.
   */
  async getIdTokenClient(targetAudience: string): Promise<IdTokenClient> {
    const client = await this.getClient();
    if (!('fetchIdToken' in client)) {
      throw new Error(
        'Cannot fetch ID token in this environment, use GCE or set the GOOGLE_APPLICATION_CREDENTIALS environment variable to a service account credentials JSON file.'
      );
    }
    return new IdTokenClient({targetAudience, idTokenProvider: client});
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
    return client.getRequestHeaders(url);
  }

  /**
   * Obtain credentials for a request, then attach the appropriate headers to
   * the request options.
   * @param opts Axios or Request options on which to attach the headers
   */
  async authorizeRequest(opts: {
    url?: string;
    uri?: string;
    headers?: Headers;
  }) {
    opts = opts || {};
    const url = opts.url || opts.uri;
    const client = await this.getClient();
    const headers = await client.getRequestHeaders(url);
    opts.headers = Object.assign(opts.headers || {}, headers);
    return opts;
  }

  /**
   * Automatically obtain application default credentials, and make an
   * HTTP request using the given options.
   * @param opts Axios request options for the HTTP request.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async request<T = any>(opts: GaxiosOptions): Promise<GaxiosResponse<T>> {
    const client = await this.getClient();
    return client.request<T>(opts);
  }

  /**
   * Determine the compute environment in which the code is running.
   */
  getEnv(): Promise<GCPEnv> {
    return getEnv();
  }

  /**
   * Sign the given data with the current private key, or go out
   * to the IAM API to sign it.
   * @param data The data to be signed.
   * @param endpoint A custom endpoint to use.
   *
   * @example
   * ```
   * sign('data', 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/');
   * ```
   */
  async sign(data: string, endpoint?: string): Promise<string> {
    const client = await this.getClient();
    const universe = await this.getUniverseDomain();

    endpoint =
      endpoint ||
      `https://iamcredentials.${universe}/v1/projects/-/serviceAccounts/`;

    if (client instanceof Impersonated) {
      const signed = await client.sign(data);
      return signed.signedBlob;
    }

    const crypto = createCrypto();
    if (client instanceof JWT && client.key) {
      const sign = await crypto.sign(client.key, data);
      return sign;
    }

    const creds = await this.getCredentials();
    if (!creds.client_email) {
      throw new Error('Cannot sign data without `client_email`.');
    }

    return this.signBlob(crypto, creds.client_email, data, endpoint);
  }

  private async signBlob(
    crypto: Crypto,
    emailOrUniqueId: string,
    data: string,
    endpoint: string
  ): Promise<string> {
    const url = new URL(endpoint + `${emailOrUniqueId}:signBlob`);
    const res = await this.request<SignBlobResponse>({
      method: 'POST',
      url: url.href,
      data: {
        payload: crypto.encodeBase64StringUtf8(data),
      },
    });

    return res.data.signedBlob;
  }
}

export interface SignBlobResponse {
  keyId: string;
  signedBlob: string;
}
