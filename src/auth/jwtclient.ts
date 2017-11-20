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
import * as request from 'request';
import * as stream from 'stream';

import {Credentials, JWTInput} from './credentials';
import {JWTAccess} from './jwtaccess';
import {OAuth2Client} from './oauth2client';

const isString = require('lodash.isstring');
const noop = Function.prototype;

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
   * @param {function} metadataCb
   */
  getRequestMetadata(
      optUri: string|null,
      metadataCb: (err: Error|null, result?: {}|null) => void) {
    if (this.createScopedRequired() && optUri) {
      // no scopes have been set, but a uri has been provided.  Use JWTAccess
      // credentials.
      const alt = new JWTAccess(this.email, this.key);
      return alt.getRequestMetadata(optUri, metadataCb);
    } else {
      return super.getRequestMetadata(optUri, metadataCb);
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
   */
  authorize(callback?: (err: Error|null, result: Credentials) => void) {
    const done = callback || noop;
    this.refreshToken(null, (err, result) => {
      if (err) {
        done(err);
      } else if (!result) {
        done(new Error('No result returned'));
      } else {
        this.credentials = result;
        this.credentials.refresh_token = 'jwt-placeholder';
        this.key = this.gtoken.key;
        this.email = this.gtoken.iss;
        done(null, result);
      }
    });
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored
   * @param {function=} callback Optional callback.
   * @private
   */
  refreshToken(
      ignored: string|null,
      callback?: (err: Error, credentials?: Credentials) => void) {
    const done = callback || noop;
    return this.createGToken((err, newGToken) => {
      if (err) {
        return done(err);
      } else {
        return newGToken.getToken((err2?: Error|null, token?: string|null) => {
          return done(err2, {
            access_token: token,
            token_type: 'Bearer',
            expiry_date: newGToken.expiresAt
          });
        });
      }
    });
  }

  /**
   * Create a JWT credentials instance using the given input options.
   * @param {object=} json The input object.
   * @param {function=} callback Optional callback.
   */
  fromJSON(json: JWTInput, callback?: (err?: Error) => void) {
    const done = callback || noop;
    if (!json) {
      done(new Error(
          'Must pass in a JSON object containing the service account auth settings.'));
      return;
    }
    if (!json.client_email) {
      done(new Error(
          'The incoming JSON object does not contain a client_email field'));
      return;
    }
    if (!json.private_key) {
      done(new Error(
          'The incoming JSON object does not contain a private_key field'));
      return;
    }
    // Extract the relevant information from the json key file.
    this.email = json.client_email;
    this.key = json.private_key;
    this.projectId = json.project_id;
    done();
  }

  /**
   * Create a JWT credentials instance using the given input stream.
   * @param {object=} inputStream The input stream.
   * @param {function=} callback Optional callback.
   */
  fromStream(
      inputStream: stream.Readable, callback: (err?: Error|null) => void) {
    const done = callback || noop;
    if (!inputStream) {
      setImmediate(() => {
        done(new Error(
            'Must pass in a stream containing the service account auth settings.'));
      });
      return;
    }
    let s = '';
    inputStream.setEncoding('utf8');
    inputStream.on('data', (chunk) => {
      s += chunk;
    });
    inputStream.on('end', () => {
      try {
        const data = JSON.parse(s);
        this.fromJSON(data, callback);
      } catch (err) {
        done(err);
      }
    });
  }

  /**
   * Creates a JWT credentials instance using an API Key for authentication.
   * @param {string} apiKey - the API Key in string form.
   * @param {function=} callback - Optional callback to be invoked after
   *  initialization.
   */
  fromAPIKey(apiKey: string, callback?: (err: Error) => void) {
    const done = callback || noop;
    if (!isString(apiKey)) {
      setImmediate(() => {
        done(new Error('Must provide an API Key string.'));
      });
      return;
    }
    this.apiKey = apiKey;
    done(null);
  }

  /**
   * Creates the gToken instance if it has not been created already.
   * @param {function=} callback Callback.
   * @private
   */
  private createGToken(
      callback: (err: Error|null, token: GoogleToken) => void) {
    if (this.gtoken) {
      return callback(null, this.gtoken);
    } else {
      const opts = {
        iss: this.email,
        sub: this.subject,
        scope: this.scopes,
        keyFile: this.keyFile,
        key: this.key
      } as TokenOptions;
      this.gtoken = new GoogleToken(opts);
      return callback(null, this.gtoken);
    }
  }
}
