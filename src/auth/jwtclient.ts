/**
 * Copyright 2013 Google Inc. All Rights Reserved.
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

import {GoogleToken, TokenOptions} from 'gtoken';
import * as stream from 'stream';

import {Credentials, JWTInput} from './credentials';
import {JWTAccess} from './jwtaccess';
import {GetTokenResponse, OAuth2Client, RequestMetadataResponse} from './oauth2client';

const isString = require('lodash.isstring');

export class JWT extends OAuth2Client {
  email?: string;
  keyFile?: string|null;
  key?: string|null;
  scopes?: string|string[]|null;
  scope?: string|null;
  subject?: string;
  gtoken: GoogleToken;

  /**
   * JWT service account credentials.
   *
   * Retrieve access token using gtoken.
   *
   * @param {string=} email service account email address.
   * @param {string=} keyFile path to private key file.
   * @param {string=} key value of key
   * @param {(string|array)=} scopes list of requested scopes or a single scope.
   * @param {string=} subject impersonated account's email address.
   * @constructor
   */
  constructor(
      email?: string, keyFile?: string|null, key?: string|null,
      scopes?: string|string[]|null, subject?: string) {
    super();
    this.email = email;
    this.keyFile = keyFile;
    this.key = key;
    this.scopes = scopes;
    this.subject = subject;
    this.credentials = {refresh_token: 'jwt-placeholder', expiry_date: 1};
  }

  /**
   * Creates a copy of the credential with the specified scopes.
   * @param {(string|array)=} scopes List of requested scopes or a single scope.
   * @return {object} The cloned instance.
   */
  createScoped(scopes?: string|string[]) {
    return new JWT(this.email, this.keyFile, this.key, scopes, this.subject);
  }

  /**
   * Obtains the metadata to be sent with the request.
   *
   * @param {string} optUri the URI being authorized.
   */
  protected async getRequestMetadataAsync(url?: string|null):
      Promise<RequestMetadataResponse> {
    if (this.createScopedRequired() && url) {
      // no scopes have been set, but a uri has been provided.  Use JWTAccess
      // credentials.
      const alt = new JWTAccess(this.email, this.key);
      return alt.getRequestMetadata(url);
    } else {
      return super.getRequestMetadataAsync(url);
    }
  }

  /**
   * Indicates whether the credential requires scopes to be created by calling
   * createdScoped before use.
   * @return {boolean} false if createScoped does not need to be called.
   */
  createScopedRequired() {
    // If scopes is null, always return true.
    if (this.scopes) {
      // For arrays, check the array length.
      if (this.scopes instanceof Array) {
        return this.scopes.length === 0;
      }
      // For others, convert to a string and check the length.
      return String(this.scopes).length === 0;
    }
    return true;
  }

  /**
   * Get the initial access token using gToken.
   * @param {function=} callback Optional callback.
   * @returns Promise that resolves with credentials
   */
  authorize(): Promise<Credentials>;
  authorize(callback: (err: Error|null, result?: Credentials) => void): void;
  authorize(callback?: (err: Error|null, result?: Credentials) => void):
      Promise<Credentials>|void {
    if (callback) {
      this.authorizeAsync().then(r => callback(null, r)).catch(callback);
    } else {
      return this.authorizeAsync();
    }
  }

  private async authorizeAsync(): Promise<Credentials> {
    const result = await this.refreshToken();
    if (!result) {
      throw new Error('No result returned');
    }
    this.credentials = result.tokens;
    this.credentials.refresh_token = 'jwt-placeholder';
    this.key = this.gtoken.key;
    this.email = this.gtoken.iss;
    return result.tokens;
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored
   * @private
   */
  async refreshToken(refreshToken?: string|null): Promise<GetTokenResponse> {
    const newGToken = this.createGToken();
    const token = await newGToken.getToken();
    const tokens = {
      access_token: token,
      token_type: 'Bearer',
      expiry_date: newGToken.expiresAt
    };
    return {res: null, tokens};
  }

  /**
   * Create a JWT credentials instance using the given input options.
   * @param {object=} json The input object.
   */
  fromJSON(json: JWTInput): void {
    if (!json) {
      throw new Error(
          'Must pass in a JSON object containing the service account auth settings.');
    }
    if (!json.client_email) {
      throw new Error(
          'The incoming JSON object does not contain a client_email field');
    }
    if (!json.private_key) {
      throw new Error(
          'The incoming JSON object does not contain a private_key field');
    }
    // Extract the relevant information from the json key file.
    this.email = json.client_email;
    this.key = json.private_key;
    this.projectId = json.project_id;
  }

  /**
   * Create a JWT credentials instance using the given input stream.
   * @param {object=} inputStream The input stream.
   * @param {function=} callback Optional callback.
   */
  fromStream(inputStream: stream.Readable): Promise<void>;
  fromStream(
      inputStream: stream.Readable, callback: (err?: Error|null) => void): void;
  fromStream(
      inputStream: stream.Readable,
      callback?: (err?: Error|null) => void): void|Promise<void> {
    if (callback) {
      this.fromStreamAsync(inputStream).then(r => callback()).catch(callback);
    } else {
      return this.fromStreamAsync(inputStream);
    }
  }

  private fromStreamAsync(inputStream: stream.Readable) {
    return new Promise<void>((resolve, reject) => {
      if (!inputStream) {
        throw new Error(
            'Must pass in a stream containing the service account auth settings.');
      }
      let s = '';
      inputStream.setEncoding('utf8');
      inputStream.on('data', (chunk) => {
        s += chunk;
      });
      inputStream.on('end', () => {
        try {
          const data = JSON.parse(s);
          this.fromJSON(data);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  /**
   * Creates a JWT credentials instance using an API Key for authentication.
   * @param {string} apiKey - the API Key in string form.
   */
  fromAPIKey(apiKey: string): void {
    if (!isString(apiKey)) {
      throw new Error('Must provide an API Key string.');
    }
    this.apiKey = apiKey;
  }

  /**
   * Creates the gToken instance if it has not been created already.
   * @param {function=} callback Callback.
   * @private
   */
  private createGToken() {
    if (!this.gtoken) {
      this.gtoken = new GoogleToken({
        iss: this.email,
        sub: this.subject,
        scope: this.scopes,
        keyFile: this.keyFile,
        key: this.key
      } as TokenOptions);
    }
    return this.gtoken;
  }
}
