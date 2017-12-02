/**
 * Copyright 2012 Google Inc. All Rights Reserved.
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

import {AxiosError, AxiosPromise, AxiosRequestConfig, AxiosResponse} from 'axios';
import * as http from 'http';
import * as querystring from 'querystring';

import {PemVerifier} from './../pemverifier';
import {BodyResponseCallback} from './../transporters';
import {AuthClient} from './authclient';
import {CredentialRequest, Credentials} from './credentials';
import {LoginTicket} from './loginticket';

<<<<<<< HEAD
const merge = require('lodash.merge');
const isString = require('lodash.isstring');

=======
>>>>>>> 98b2b1a... chore: switch to axios (#182)
export interface GenerateAuthUrlOpts {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string[]|string;
  state?: string;
}

export interface AuthClientOpts {
  authBaseUrl?: string;
  tokenUrl?: string;
}

export interface GetTokenCallback {
  (err: AxiosError|null, token?: Credentials|null,
   res?: AxiosResponse|null): void;
}

export interface GetTokenResponse {
  tokens: Credentials;
  res: AxiosResponse|null;
}

export interface GetAccessTokenCallback {
  (err: AxiosError|null, token?: string|null, res?: AxiosResponse|null): void;
}

export interface GetAccessTokenResponse {
  token?: string|null;
  res?: AxiosResponse|null;
}

export interface RefreshAccessTokenCallback {
  (err: AxiosError|null, credentials?: Credentials|null,
   res?: AxiosResponse|null): void;
}

export interface RefreshAccessTokenResponse {
  credentials: Credentials;
  res: AxiosResponse|null;
}

export interface RequestMetadataResponse {
  headers: http.IncomingHttpHeaders;
  res?: AxiosResponse<void>|null;
}

export interface RequestMetadataCallback {
  (err: AxiosError|null, headers?: http.IncomingHttpHeaders,
   res?: AxiosResponse<void>|null): void;
}

export interface GetFederatedSignonCertsCallback {
  // tslint:disable-next-line no-any
  (err: AxiosError|null, certs?: any,
   response?: AxiosResponse<void>|null): void;
}

export interface FederatedSignonCertsResponse {
  // tslint:disable-next-line no-any
  certs: any;
  res?: AxiosResponse<void>|null;
}

export interface RevokeCredentialsResult { success: boolean; }

export class OAuth2Client extends AuthClient {
  private redirectUri?: string;
  private certificateCache: {}|null|undefined = null;
  private certificateExpiry: Date|null = null;
  protected opts: AuthClientOpts;

  // TODO: refactor tests to make this private
  _clientId?: string;

  // TODO: refactor tests to make this private
  _clientSecret?: string;

  apiKey: string;

  projectId?: string;

  /**
   * Handles OAuth2 flow for Google APIs.
   *
   * @param {string=} clientId The authentication client ID.
   * @param {string=} clientSecret The authentication client secret.
   * @param {string=} redirectUri The URI to redirect to after completing the auth request.
   * @param {Object=} opts optional options for overriding the given parameters.
   * @constructor
   */
  constructor(
      clientId?: string, clientSecret?: string, redirectUri?: string,
      opts: AuthClientOpts = {}) {
    super();
    this._clientId = clientId;
    this._clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.opts = opts;
    this.credentials = {};
  }

  /**
   * The base URL for auth endpoints.
   */
  private static readonly GOOGLE_OAUTH2_AUTH_BASE_URL_ =
      'https://accounts.google.com/o/oauth2/auth';

  /**
   * The base endpoint for token retrieval.
   */
  private static readonly GOOGLE_OAUTH2_TOKEN_URL_ =
      'https://accounts.google.com/o/oauth2/token';

  /**
   * The base endpoint to revoke tokens.
   */
  private static readonly GOOGLE_OAUTH2_REVOKE_URL_ =
      'https://accounts.google.com/o/oauth2/revoke';

  /**
   * Google Sign on certificates.
   */
  private static readonly GOOGLE_OAUTH2_FEDERATED_SIGNON_CERTS_URL_ =
      'https://www.googleapis.com/oauth2/v1/certs';

  /**
   * Clock skew - five minutes in seconds
   */
  private static readonly CLOCK_SKEW_SECS_ = 300;

  /**
   * Max Token Lifetime is one day in seconds
   */
  private static readonly MAX_TOKEN_LIFETIME_SECS_ = 86400;

  /**
   * The allowed oauth token issuers.
   */
  private static readonly ISSUERS_ =
      ['accounts.google.com', 'https://accounts.google.com'];

  /**
   * Generates URL for consent page landing.
   * @param {object=} opts Options.
   * @return {string} URL to consent page.
   */
  generateAuthUrl(opts: GenerateAuthUrlOpts = {}) {
    opts.response_type = opts.response_type || 'code';
    opts.client_id = opts.client_id || this._clientId;
    opts.redirect_uri = opts.redirect_uri || this.redirectUri;

    // Allow scopes to be passed either as array or a string
    if (opts.scope instanceof Array) {
      opts.scope = opts.scope.join(' ');
    }

    const rootUrl =
        this.opts.authBaseUrl || OAuth2Client.GOOGLE_OAUTH2_AUTH_BASE_URL_;

    return rootUrl + '?' + querystring.stringify(opts);
  }

  /**
   * Gets the access token for the given code.
   * @param {string} code The authorization code.
   * @param {function=} callback Optional callback fn.
   */
  getToken(code: string): Promise<GetTokenResponse>;
  getToken(code: string, callback: GetTokenCallback): void;
  getToken(code: string, callback?: GetTokenCallback):
      Promise<GetTokenResponse>|void {
    if (callback) {
      this.getTokenAsync(code)
          .then(r => callback(null, r.tokens, r.res))
          .catch(e => callback(e, null, (e as AxiosError).response));
    } else {
      return this.getTokenAsync(code);
    }
  }

  private async getTokenAsync(code: string): Promise<GetTokenResponse> {
    const url = this.opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
    const values = {
      code,
      client_id: this._clientId,
      client_secret: this._clientSecret,
      redirect_uri: this.redirectUri,
      grant_type: 'authorization_code'
    };

    const res = await this.transporter.request<CredentialRequest>({
      method: 'POST',
      url,
      data: querystring.stringify(values),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'}
    });

    const tokens = res.data as Credentials;
    if (res.data && res.data.expires_in) {
      tokens.expiry_date =
          ((new Date()).getTime() + (res.data.expires_in * 1000));
      delete (tokens as CredentialRequest).expires_in;
    }

    return {tokens, res};
  }

  /**
   * Refreshes the access token.
   * @param {string} refresh_token Existing refresh token.
   * @param {function=} callback Optional callback.
   * @private
   */
  protected async refreshToken(refreshToken?: string|
                               null): Promise<GetTokenResponse> {
    const url = this.opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
    const data = {
      refresh_token: refreshToken,
      client_id: this._clientId,
      client_secret: this._clientSecret,
      grant_type: 'refresh_token'
    };

    // request for new token
    const res = await this.transporter.request<CredentialRequest>({
      method: 'POST',
      url,
      data: querystring.stringify(data),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'}
    });
    const tokens = res.data as Credentials;
    // TODO: de-duplicate this code from a few spots
    if (res.data && res.data.expires_in) {
      tokens.expiry_date =
          ((new Date()).getTime() + (res.data.expires_in * 1000));
      delete (tokens as CredentialRequest).expires_in;
    }
    return {tokens, res};
  }

  /**
   * Retrieves the access token using refresh token
   *
   * @deprecated use getRequestMetadata instead.
   * @param {function} callback callback
   */

  refreshAccessToken(): Promise<RefreshAccessTokenResponse>;
  refreshAccessToken(callback: RefreshAccessTokenCallback): void;
  refreshAccessToken(callback?: RefreshAccessTokenCallback):
      Promise<RefreshAccessTokenResponse>|void {
    if (callback) {
      this.refreshAccessTokenAsync()
          .then(r => callback(null, r.credentials, r.res))
          .catch(callback);
    } else {
      return this.refreshAccessTokenAsync();
    }
  }

  private async refreshAccessTokenAsync() {
    if (!this.credentials.refresh_token) {
      throw new Error('No refresh token is set.');
    }
    const r = await this.refreshToken(this.credentials.refresh_token);
    const tokens = r.tokens as Credentials;
    tokens.refresh_token = this.credentials.refresh_token;
    this.credentials = tokens;
    return {credentials: this.credentials, res: r.res};
  }

  /**
   * Get a non-expired access token, after refreshing if necessary
   *
   * @param {function} callback Callback to call with the access token
   */
  getAccessToken(): Promise<GetAccessTokenResponse>;
  getAccessToken(callback: GetAccessTokenCallback): void;
  getAccessToken(callback?: GetAccessTokenCallback):
      Promise<GetAccessTokenResponse>|void {
    if (callback) {
      this.getAccessTokenAsync()
          .then(r => callback(null, r.token, r.res))
          .catch(callback);
    } else {
      return this.getAccessTokenAsync();
    }
  }

  private async getAccessTokenAsync(): Promise<GetAccessTokenResponse> {
    const expiryDate = this.credentials.expiry_date;

    // if no expiry time, assume it's not expired
    const isTokenExpired =
        expiryDate ? expiryDate <= (new Date()).getTime() : false;
    if (!this.credentials.access_token && !this.credentials.refresh_token) {
      throw new Error('No access or refresh token is set.');
    }

    const shouldRefresh = !this.credentials.access_token || isTokenExpired;
    if (shouldRefresh && this.credentials.refresh_token) {
      if (!this.credentials.refresh_token) {
        throw new Error('No refresh token is set.');
      }

      const r = await this.refreshAccessToken();
      if (!r.credentials || (r.credentials && !r.credentials.access_token)) {
        throw new Error('Could not refresh access token.');
      }
      return {token: r.credentials.access_token, res: r.res};
    } else {
      return {token: this.credentials.access_token};
    }
  }

  /**
   * getRequestMetadata obtains auth metadata to be used by requests.
   *
   * getRequestMetadata is the main authentication interface.  It takes an
   * optional uri which when present is the endpoint being accessed, and a
   * callback func(err, metadata_obj, response) where metadata_obj contains
   * authorization metadata fields and response is an optional response object.
   *
   * In OAuth2Client, metadata_obj has the form.
   *
   * {Authorization: 'Bearer <access_token_value>'}
   *
   * @param {string} optUri the Uri being authorized
   * @param {function} metadataCb the func described above
   */
  getRequestMetadata(url?: string|null): Promise<RequestMetadataResponse>;
  getRequestMetadata(url: string|null, callback: RequestMetadataCallback): void;
  getRequestMetadata(url: string|null, callback?: RequestMetadataCallback):
      Promise<RequestMetadataResponse>|void {
    if (callback) {
      this.getRequestMetadataAsync(url)
          .then(r => callback(null, r.headers, r.res))
          .catch(callback);
    } else {
      return this.getRequestMetadataAsync(url);
    }
  }

  protected async getRequestMetadataAsync(url?: string|null):
      Promise<RequestMetadataResponse> {
    const thisCreds = this.credentials;
    if (!thisCreds.access_token && !thisCreds.refresh_token && !this.apiKey) {
      throw new Error('No access, refresh token or API key is set.');
    }

    // if no expiry time, assume it's not expired
    const expiryDate = thisCreds.expiry_date;
    const isTokenExpired =
        expiryDate ? expiryDate <= (new Date()).getTime() : false;

    if (thisCreds.access_token && !isTokenExpired) {
      thisCreds.token_type = thisCreds.token_type || 'Bearer';
      const headers = {
        Authorization: thisCreds.token_type + ' ' + thisCreds.access_token
      };
      return {headers};
    }

    if (this.apiKey) {
      return {headers: {}};
    }
    let r: GetTokenResponse|null = null;
    let tokens: Credentials|null = null;
    try {
      r = await this.refreshToken(thisCreds.refresh_token);
      tokens = r.tokens;
    } catch (err) {
      const e = err as AxiosError;
      if (e.response &&
          (e.response.status === 403 || e.response.status === 404)) {
        e.message = 'Could not refresh access token.';
      }
      throw e;
    }

    const credentials = this.credentials;
    credentials.token_type = credentials.token_type || 'Bearer';
    tokens.refresh_token = credentials.refresh_token;
    this.credentials = tokens;
    const headers = {
      Authorization: credentials.token_type + ' ' + tokens.access_token
    };
    return {headers, res: r.res};
  }

  /**
   * Revokes the access given to token.
   * @param {string} token The existing token to be revoked.
   * @param {function=} callback Optional callback fn.
   */
  revokeToken(token: string): AxiosPromise<RevokeCredentialsResult>;
  revokeToken(
      token: string,
      callback: BodyResponseCallback<RevokeCredentialsResult>): void;
  revokeToken(
      token: string, callback?: BodyResponseCallback<RevokeCredentialsResult>):
      AxiosPromise<RevokeCredentialsResult>|void {
    const opts = {
      url: OAuth2Client.GOOGLE_OAUTH2_REVOKE_URL_ + '?' +
          querystring.stringify({token})
    };
    if (callback) {
      this.transporter.request<RevokeCredentialsResult>(opts)
          .then(res => {
            callback(null, res);
          })
          .catch(callback);
    } else {
      return this.transporter.request<RevokeCredentialsResult>(opts);
    }
  }


  /**
   * Revokes access token and clears the credentials object
   * @param  {Function=} callback callback
   */
  revokeCredentials(): AxiosPromise<RevokeCredentialsResult>;
  revokeCredentials(callback: BodyResponseCallback<RevokeCredentialsResult>):
      void;
  revokeCredentials(callback?: BodyResponseCallback<RevokeCredentialsResult>):
      AxiosPromise<RevokeCredentialsResult>|void {
    if (callback) {
      this.revokeCredentialsAsync()
          .then(res => callback(null, res))
          .catch(callback);
    } else {
      return this.revokeCredentialsAsync();
    }
  }

  private async revokeCredentialsAsync() {
    const token = this.credentials.access_token;
    this.credentials = {};
    if (token) {
      return this.revokeToken(token);
    } else {
      throw new Error('No access token to revoke.');
    }
  }

  /**
   * Provides a request implementation with OAuth 2.0 flow.
   * If credentials have a refresh_token, in cases of HTTP
   * 401 and 403 responses, it automatically asks for a new
   * access token and replays the unsuccessful request.
   * @param {object} opts Request options.
   * @param {function} callback callback.
   * @return {Request} Request object
   */
  request<T>(opts: AxiosRequestConfig): AxiosPromise<T>;
  request<T>(opts: AxiosRequestConfig, callback: BodyResponseCallback<T>): void;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      AxiosPromise<T>|void {
    if (callback) {
      this.requestAsync<T>(opts).then(r => callback(null, r)).catch(e => {
        const err = e as AxiosError;
        const body = err.response ? err.response.data : null;
        return callback(e, err.response);
      });
    } else {
      return this.requestAsync<T>(opts);
    }
  }

  protected async requestAsync<T>(opts: AxiosRequestConfig, retry = false):
      Promise<AxiosResponse<T>> {
    let r2: AxiosResponse;
    try {
      const r = await this.getRequestMetadataAsync(null);
      if (r.headers && r.headers.Authorization) {
        opts.headers = opts.headers || {};
        opts.headers.Authorization = r.headers.Authorization;
      }

      if (this.apiKey) {
        opts.params = Object.assign(opts.params || {}, {key: this.apiKey});
      }
      r2 = await this.transporter.request<T>(opts);
    } catch (e) {
      const res = (e as AxiosError).response;
      if (res) {
        const statusCode = res.status;
        // Automatically retry 401 and 403 responses if err is set and is
        // unrelated to response then getting credentials failed, and retrying
        // won't help
        if (!retry && (statusCode === 401 || statusCode === 403)) {
          /* It only makes sense to retry once, because the retry is intended
           * to handle expiration-related failures. If refreshing the token
           * does not fix the failure, then refreshing again probably won't
           * help */
          await this.refreshAccessTokenAsync();
          return this.requestAsync<T>(opts, true);
        }
      }
      throw e;
    }
    return r2;
  }

  /**
   * Verify id token is token by checking the certs and audience
   * @param {string} idToken ID Token.
   * @param {(string|Array.<string>)} audience The audience to verify against the ID Token
   * @param {function=} callback Callback supplying GoogleLogin if successful
   */
  verifyIdToken(idToken: string, audience: string|string[]):
      Promise<LoginTicket|null>;
  verifyIdToken(
      idToken: string, audience: string|string[],
      callback: (err: Error|null, login?: LoginTicket|null) => void): void;
  verifyIdToken(
      idToken: string, audience: string|string[],
      callback?: (err: Error|null, login?: LoginTicket|null) => void):
      void|Promise<LoginTicket|null> {
    if (callback) {
      this.verifyIdTokenAsync(idToken, audience)
          .then(r => callback(null, r))
          .catch(callback);
    } else {
      return this.verifyIdTokenAsync(idToken, audience);
    }
  }

  private async verifyIdTokenAsync(idToken: string, audience: string|string[]):
      Promise<LoginTicket|null> {
    if (!idToken) {
      throw new Error('The verifyIdToken method requires an ID Token');
    }

    const certs = await this.getFederatedSignonCertsAsync();
    const login = this.verifySignedJwtWithCerts(
        idToken, certs, audience, OAuth2Client.ISSUERS_);
    return login;
  }

  /**
   * Gets federated sign-on certificates to use for verifying identity tokens.
   * Returns certs as array structure, where keys are key ids, and values
   * are PEM encoded certificates.
   * @param {function=} callback Callback supplying the certificates
   */
  getFederatedSignonCerts(): Promise<FederatedSignonCertsResponse>;
  getFederatedSignonCerts(callback: GetFederatedSignonCertsCallback): void;
  getFederatedSignonCerts(callback?: GetFederatedSignonCertsCallback):
      Promise<FederatedSignonCertsResponse>|void {
    if (callback) {
      this.getFederatedSignonCertsAsync()
          .then(r => callback(null, r.certs, r.res))
          .catch(callback);
    } else {
      return this.getFederatedSignonCertsAsync();
    }
  }

  async getFederatedSignonCertsAsync(): Promise<FederatedSignonCertsResponse> {
    const nowTime = (new Date()).getTime();
    if (this.certificateExpiry &&
        (nowTime < this.certificateExpiry.getTime())) {
      return {certs: this.certificateCache};
    }
    let res: AxiosResponse;
    try {
      res = await this.transporter.request(
          {url: OAuth2Client.GOOGLE_OAUTH2_FEDERATED_SIGNON_CERTS_URL_});
    } catch (e) {
      throw new Error('Failed to retrieve verification certificates: ' + e);
    }

    const cacheControl = res ? res.headers['cache-control'] : undefined;
    let cacheAge = -1;
    if (cacheControl) {
      const pattern = new RegExp('max-age=([0-9]*)');
      const regexResult = pattern.exec(cacheControl as string);
      if (regexResult && regexResult.length === 2) {
        // Cache results with max-age (in seconds)
        cacheAge = Number(regexResult[1]) * 1000;  // milliseconds
      }
    }

    const now = new Date();
    this.certificateExpiry =
        cacheAge === -1 ? null : new Date(now.getTime() + cacheAge);
    this.certificateCache = res.data;
    return {certs: res.data, res};
  }

  /**
   * Verify the id token is signed with the correct certificate
   * and is from the correct audience.
   * @param {string} jwt The jwt to verify (The ID Token in this case).
   * @param {array} certs The array of certs to test the jwt against.
   * @param {(string|Array.<string>)} requiredAudience The audience to test the jwt against.
   * @param {array} issuers The allowed issuers of the jwt (Optional).
   * @param {string} maxExpiry The max expiry the certificate can be (Optional).
   * @return {LoginTicket} Returns a LoginTicket on verification.
   */
  verifySignedJwtWithCerts(
      jwt: string, certs: {}, requiredAudience: string|string[],
      issuers?: string[], maxExpiry?: number) {
    if (!maxExpiry) {
      maxExpiry = OAuth2Client.MAX_TOKEN_LIFETIME_SECS_;
    }

    const segments = jwt.split('.');
    if (segments.length !== 3) {
      throw new Error('Wrong number of segments in token: ' + jwt);
    }
    const signed = segments[0] + '.' + segments[1];
    const signature = segments[2];

    let envelope;
    let payload;

    try {
      envelope = JSON.parse(this.decodeBase64(segments[0]));
    } catch (err) {
      throw new Error('Can\'t parse token envelope: ' + segments[0]);
    }

    if (!envelope) {
      throw new Error('Can\'t parse token envelope: ' + segments[0]);
    }

    try {
      payload = JSON.parse(this.decodeBase64(segments[1]));
    } catch (err) {
      throw new Error('Can\'t parse token payload: ' + segments[0]);
    }

    if (!payload) {
      throw new Error('Can\'t parse token payload: ' + segments[1]);
    }

    if (!certs.hasOwnProperty(envelope.kid)) {
      // If this is not present, then there's no reason to attempt verification
      throw new Error('No pem found for envelope: ' + JSON.stringify(envelope));
    }
    // certs is a legit dynamic object
    // tslint:disable-next-line no-any
    const pem = (certs as any)[envelope.kid];
    const pemVerifier = new PemVerifier();
    const verified = pemVerifier.verify(pem, signed, signature, 'base64');

    if (!verified) {
      throw new Error('Invalid token signature: ' + jwt);
    }

    if (!payload.iat) {
      throw new Error('No issue time in token: ' + JSON.stringify(payload));
    }

    if (!payload.exp) {
      throw new Error(
          'No expiration time in token: ' + JSON.stringify(payload));
    }

    const iat = Number(payload.iat);
    if (isNaN(iat)) throw new Error('iat field using invalid format');

    const exp = Number(payload.exp);
    if (isNaN(exp)) throw new Error('exp field using invalid format');

    const now = new Date().getTime() / 1000;

    if (exp >= now + maxExpiry) {
      throw new Error(
          'Expiration time too far in future: ' + JSON.stringify(payload));
    }

    const earliest = iat - OAuth2Client.CLOCK_SKEW_SECS_;
    const latest = exp + OAuth2Client.CLOCK_SKEW_SECS_;

    if (now < earliest) {
      throw new Error(
          'Token used too early, ' + now + ' < ' + earliest + ': ' +
          JSON.stringify(payload));
    }

    if (now > latest) {
      throw new Error(
          'Token used too late, ' + now + ' > ' + latest + ': ' +
          JSON.stringify(payload));
    }

    if (issuers && issuers.indexOf(payload.iss) < 0) {
      throw new Error(
          'Invalid issuer, expected one of [' + issuers + '], but got ' +
          payload.iss);
    }

    // Check the audience matches if we have one
    if (typeof requiredAudience !== 'undefined' && requiredAudience !== null) {
      const aud = payload.aud;
      let audVerified = false;
      // If the requiredAudience is an array, check if it contains token
      // audience
      if (requiredAudience.constructor === Array) {
        audVerified = (requiredAudience.indexOf(aud) > -1);
      } else {
        audVerified = (aud === requiredAudience);
      }
      if (!audVerified) {
        throw new Error(
            'Wrong recipient, payload audience != requiredAudience');
      }
    }
    return new LoginTicket(envelope, payload);
  }

  /**
   * This is a utils method to decode a base64 string
   * @param {string} b64String The string to base64 decode
   * @return {string} The decoded string
   */
  decodeBase64(b64String: string) {
    const buffer = new Buffer(b64String, 'base64');
    return buffer.toString('utf8');
  }
}
