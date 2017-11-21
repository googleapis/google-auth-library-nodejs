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

import * as querystring from 'querystring';
import * as request from 'request';

import {PemVerifier} from './../pemverifier';
import {BodyResponseCallback, RequestError} from './../transporters';
import {AuthClient} from './authclient';
import {Credentials} from './credentials';
import {LoginTicket} from './loginticket';

const merge = require('lodash.merge');
const isString = require('lodash.isstring');

export interface GenerateAuthUrlOpts {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string[]|string;
  state?: string;
}

const noop = Function.prototype;

export class OAuth2Client extends AuthClient {
  private _redirectUri: string;
  private _certificateCache: any = null;
  private _certificateExpiry: Date = null;
  protected _opts: any;
  public _clientId: string;
  public _clientSecret: string;
  public apiKey: string;

  /**
   * Handles OAuth2 flow for Google APIs.
   *
   * @param {string=} clientId The authentication client ID.
   * @param {string=} clientSecret The authentication client secret.
   * @param {string=} redirectUri The URI to redirect to after completing the auth request.
   * @param {Object=} opt_opts optional options for overriding the given parameters.
   * @constructor
   */
  constructor(
      clientId?: string, clientSecret?: string, redirectUri?: string,
      opt_opts?: any) {
    super();
    this._clientId = clientId;
    this._clientSecret = clientSecret;
    this._redirectUri = redirectUri;
    this._opts = opt_opts || {};
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
   * @param {object=} opt_opts Options.
   * @return {string} URL to consent page.
   */
  public generateAuthUrl(opt_opts?: GenerateAuthUrlOpts) {
    const opts = opt_opts || {};
    opts.response_type = opts.response_type || 'code';
    opts.client_id = opts.client_id || this._clientId;
    opts.redirect_uri = opts.redirect_uri || this._redirectUri;

    // Allow scopes to be passed either as array or a string
    if (opts.scope instanceof Array) {
      opts.scope = opts.scope.join(' ');
    }

    const rootUrl =
        this._opts.authBaseUrl || OAuth2Client.GOOGLE_OAUTH2_AUTH_BASE_URL_;

    return rootUrl + '?' + querystring.stringify(opts);
  }

  /**
   * Gets the access token for the given code.
   * @param {string} code The authorization code.
   * @param {function=} callback Optional callback fn.
   */
  public getToken(code: string, callback?: BodyResponseCallback) {
    const uri = this._opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
    const values = {
      code: code,
      client_id: this._clientId,
      client_secret: this._clientSecret,
      redirect_uri: this._redirectUri,
      grant_type: 'authorization_code'
    };

    this.transporter.request(
        {method: 'POST', uri: uri, form: values, json: true},
        (err, tokens, response) => {
          if (!err && tokens && tokens.expires_in) {
            tokens.expiry_date =
                ((new Date()).getTime() + (tokens.expires_in * 1000));
            delete tokens.expires_in;
          }
          const done = callback || noop;
          done(err, tokens, response);
        });
  }

  /**
   * Refreshes the access token.
   * @param {string} refresh_token Existing refresh token.
   * @param {function=} callback Optional callback.
   * @private
   */
  protected refreshToken(refresh_token: any, callback?: BodyResponseCallback):
      request.Request|void {
    const uri = this._opts.tokenUrl || OAuth2Client.GOOGLE_OAUTH2_TOKEN_URL_;
    const values = {
      refresh_token: refresh_token,
      client_id: this._clientId,
      client_secret: this._clientSecret,
      grant_type: 'refresh_token'
    };

    // request for new token
    return this.transporter.request(
        {method: 'POST', uri: uri, form: values, json: true},
        (err, tokens, response) => {
          if (!err && tokens && tokens.expires_in) {
            tokens.expiry_date =
                ((new Date()).getTime() + (tokens.expires_in * 1000));
            delete tokens.expires_in;
          }
          const done = callback || noop;
          done(err, tokens, response);
        });
  }

  /**
   * Retrieves the access token using refresh token
   *
   * @deprecated use getRequestMetadata instead.
   * @param {function} callback callback
   */
  public refreshAccessToken(
      callback:
          (err: Error, credentials: Credentials,
           response?: request.RequestResponse) => void) {
    if (!this.credentials.refresh_token) {
      callback(new Error('No refresh token is set.'), null);
      return;
    }

    this.refreshToken(
        this.credentials.refresh_token, (err, result, response) => {
          if (err) {
            callback(err, null, response);
          } else {
            const tokens = result;
            tokens.refresh_token = this.credentials.refresh_token;
            this.credentials = tokens;
            callback(null, this.credentials, response);
          }
        });
  }

  /**
   * Get a non-expired access token, after refreshing if necessary
   *
   * @param {function} callback Callback to call with the access token
   */
  public getAccessToken(
      callback:
          (err: Error, access_token: string,
           response?: request.RequestResponse) => void) {
    const expiryDate = this.credentials.expiry_date;

    // if no expiry time, assume it's not expired
    const isTokenExpired =
        expiryDate ? expiryDate <= (new Date()).getTime() : false;

    if (!this.credentials.access_token && !this.credentials.refresh_token) {
      return callback(new Error('No access or refresh token is set.'), null);
    }

    const shouldRefresh = !this.credentials.access_token || isTokenExpired;
    if (shouldRefresh && this.credentials.refresh_token) {
      if (!this.credentials.refresh_token) {
        return callback(new Error('No refresh token is set.'), null);
      }

      this.refreshAccessToken((err, tokens, response) => {
        if (err) {
          return callback(err, null, response);
        }
        if (!tokens || (tokens && !tokens.access_token)) {
          return callback(
              new Error('Could not refresh access token.'), null, response);
        }
        return callback(null, tokens.access_token, response);
      });
    } else {
      return callback(null, this.credentials.access_token, null);
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
   * @param {string} opt_uri the Uri being authorized
   * @param {function} metadataCb the func described above
   */
  public getRequestMetadata(
      opt_uri: string,
      metadataCb:
          (err: Error, headers: any,
           response?: request.RequestResponse) => void) {
    const thisCreds = this.credentials;

    if (!thisCreds.access_token && !thisCreds.refresh_token && !this.apiKey) {
      return metadataCb(
          new Error('No access, refresh token or API key is set.'), null);
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
      return metadataCb(null, headers, null);
    }

    if (this.apiKey) {
      return metadataCb(null, {}, null);
    }

    return this.refreshToken(
        thisCreds.refresh_token, (err, tokens, response) => {
          // If the error code is 403 or 404, go to the else so the error
          // message is replaced. Otherwise, return the error.
          if (err && (err as RequestError).code !== 403 &&
              (err as RequestError).code !== 404) {
            return metadataCb(err, null, response);
          } else {
            if (!tokens || (tokens && !tokens.access_token)) {
              return metadataCb(
                  new Error('Could not refresh access token.'), null, response);
            }

            const credentials = this.credentials;
            credentials.token_type = credentials.token_type || 'Bearer';
            tokens.refresh_token = credentials.refresh_token;
            this.credentials = tokens;
            const headers = {
              Authorization: credentials.token_type + ' ' + tokens.access_token
            };
            return metadataCb(err, headers, response);
          }
        });
  }

  /**
   * Revokes the access given to token.
   * @param {string} token The existing token to be revoked.
   * @param {function=} callback Optional callback fn.
   */
  public revokeToken(token: string, callback?: BodyResponseCallback) {
    this.transporter.request(
        {
          uri: OAuth2Client.GOOGLE_OAUTH2_REVOKE_URL_ + '?' +
              querystring.stringify({token: token}),
          json: true
        },
        callback);
  }

  /**
   * Revokes access token and clears the credentials object
   * @param  {Function=} callback callback
   */
  public revokeCredentials(callback: BodyResponseCallback) {
    const token = this.credentials.access_token;
    this.credentials = {};
    if (token) {
      this.revokeToken(token, callback);
    } else {
      callback(new RequestError('No access token to revoke.'), null, null);
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
  public request(opts?: any, callback?: BodyResponseCallback) {
    /* jshint latedef:false */

    // Callbacks will close over this to ensure that we only retry once
    let retry = true;
    let unusedUri: string = null;

    // Declare authCb upfront to avoid the linter complaining about use before
    // declaration.
    let authCb: BodyResponseCallback;

    // Hook the callback routine to call the _postRequest method.
    const postRequestCb =
        (err: Error, body: any, resp: request.RequestResponse) => {
          const statusCode = resp && resp.statusCode;
          // Automatically retry 401 and 403 responses
          // if err is set and is unrelated to response
          // then getting credentials failed, and retrying won't help
          if (retry && (statusCode === 401 || statusCode === 403) &&
              (!err || (err as RequestError).code === statusCode)) {
            /* It only makes sense to retry once, because the retry is intended
             * to handle expiration-related failures. If refreshing the token
             * does not fix the failure, then refreshing again probably won't
             * help */
            retry = false;
            // Force token refresh
            this.refreshAccessToken(() => {
              this.getRequestMetadata(unusedUri, authCb);
            });
          } else {
            this.postRequest(err, body, resp, callback);
          }
        };

    authCb = (err, headers, response) => {
      if (err) {
        postRequestCb(err, null, response);
      } else {
        if (headers) {
          opts.headers = opts.headers || {};
          opts.headers.Authorization = headers.Authorization;
        }
        if (this.apiKey) {
          if (opts.qs) {
            opts.qs = merge({}, opts.qs, {key: this.apiKey});
          } else {
            opts.qs = {key: this.apiKey};
          }
        }
        return this._makeRequest(opts, postRequestCb);
      }
    };

    return this.getRequestMetadata(unusedUri, authCb);
  }

  /**
   * Makes a request without paying attention to refreshing or anything
   * Assumes that all credentials are set correctly.
   * @param  {object}   opts     Options for request
   * @param  {Function} callback callback function
   * @return {Request}           The request object created
   */
  public _makeRequest(opts: any, callback: BodyResponseCallback) {
    return this.transporter.request(opts, callback);
  }

  /**
   * Allows inheriting classes to inspect and alter the request result.
   * @param {object} err Error result.
   * @param {object} result The result.
   * @param {object} result The HTTP response.
   * @param {Function} callback The callback.
   * @private
   */
  protected postRequest(
      err: Error, result: any, response: request.RequestResponse,
      callback: BodyResponseCallback) {
    callback(err, result, response);
  }

  /**
   * Verify id token is token by checking the certs and audience
   * @param {string} idToken ID Token.
   * @param {(string|Array.<string>)} audience The audience to verify against the ID Token
   * @param {function=} callback Callback supplying GoogleLogin if successful
   */
  public verifyIdToken(
      idToken: string, audience: string|string[],
      callback: (err: Error, login?: LoginTicket) => void) {
    if (!idToken || !callback) {
      throw new Error(
          'The verifyIdToken method requires both ' +
          'an ID Token and a callback method');
    }

    if (!isString(idToken)) {
      throw new Error('The ID Token has to be a string');
    }

    this.getFederatedSignonCerts(((err: Error, certs: {}) => {
                                   if (err) {
                                     callback(err, null);
                                   }
                                   let login;
                                   try {
                                     login = this.verifySignedJwtWithCerts(
                                         idToken, certs, audience,
                                         OAuth2Client.ISSUERS_);
                                   } catch (err) {
                                     callback(err);
                                     return;
                                   }

                                   callback(null, login);
                                 }).bind(this));
  }

  /**
   * Gets federated sign-on certificates to use for verifying identity tokens.
   * Returns certs as array structure, where keys are key ids, and values
   * are PEM encoded certificates.
   * @param {function=} callback Callback supplying the certificates
   */
  public getFederatedSignonCerts(callback: BodyResponseCallback) {
    const nowTime = (new Date()).getTime();
    if (this._certificateExpiry &&
        (nowTime < this._certificateExpiry.getTime())) {
      callback(null, this._certificateCache);
      return;
    }

    this.transporter.request(
        {
          method: 'GET',
          uri: OAuth2Client.GOOGLE_OAUTH2_FEDERATED_SIGNON_CERTS_URL_,
          json: true
        },
        (err, body, response) => {
          if (err) {
            callback(
                new RequestError(
                    'Failed to retrieve verification certificates: ' + err),
                null, response);
            return;
          }
          const cacheControl = response.headers['cache-control'];
          let cacheAge = -1;
          if (cacheControl) {
            const pattern = new RegExp('max-age=([0-9]*)');
            const regexResult = pattern.exec(cacheControl);
            if (regexResult.length === 2) {
              // Cache results with max-age (in seconds)
              cacheAge = Number(regexResult[1]) * 1000;  // milliseconds
            }
          }

          const now = new Date();
          this._certificateExpiry =
              cacheAge === -1 ? null : new Date(now.getTime() + cacheAge);
          this._certificateCache = body;
          callback(null, body, response);
        });
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
  public verifySignedJwtWithCerts(
      jwt: string, certs: any, requiredAudience: string|string[],
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
    const pem = certs[envelope.kid];
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

    const iat = parseInt(payload.iat, 10);
    const exp = parseInt(payload.exp, 10);
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
  public decodeBase64(b64String: string) {
    const buffer = new Buffer(b64String, 'base64');
    return buffer.toString('utf8');
  }
}
