/**
 * Copyright 2015 Google Inc. All Rights Reserved.
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

import * as request from 'request';

import Auth2Client from './oauth2client';

export default class UserRefreshClient extends Auth2Client {
  public _refreshToken: string;

  /**
   * User Refresh Token credentials.
   *
   * @param {string} clientId The authentication client ID.
   * @param {string} clientSecret The authentication client secret.
   * @param {string} refreshToken The authentication refresh token.
   * @constructor
   */
  constructor(clientId?: string, clientSecret?: string, refreshToken?: string) {
    super(clientId, clientSecret);
    // Named to avoid collision with the method refreshToken_
    this._refreshToken = refreshToken;
  }

  // Executes the given callback if it is not null.
  private callback(c, err?, res?) {
    if (c) {
      c(err, res);
    }
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored_
   * @param {function=} opt_callback Optional callback.
   * @private
   */
  protected refreshToken(ignored_, opt_callback): request.Request {
    return super.refreshToken(this._refreshToken, opt_callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * options.
   * @param {object=} json The input object.
   * @param {function=} opt_callback Optional callback.
   */
  public fromJSON(json, opt_callback) {
    if (!json) {
      this.callback(
          opt_callback,
          new Error(
              'Must pass in a JSON object containing the user refresh token'));
      return;
    }
    if (json.type !== 'authorized_user') {
      this.callback(
          opt_callback,
          new Error(
              'The incoming JSON object does not have the "authorized_user" type'));
      return;
    }
    if (!json.client_id) {
      this.callback(
          opt_callback,
          new Error(
              'The incoming JSON object does not contain a client_id field'));
      return;
    }
    if (!json.client_secret) {
      this.callback(
          opt_callback,
          new Error(
              'The incoming JSON object does not contain a client_secret field'));
      return;
    }
    if (!json.refresh_token) {
      this.callback(
          opt_callback,
          new Error(
              'The incoming JSON object does not contain a refresh_token field'));
      return;
    }
    this._clientId = json.client_id;
    this._clientSecret = json.client_secret;
    this._refreshToken = json.refresh_token;
    this.credentials.refresh_token = json.refresh_token;
    this.callback(opt_callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * stream.
   * @param {object=} stream The input stream.
   * @param {function=} opt_callback Optional callback.
   */
  public fromStream(stream, opt_callback) {
    if (!stream) {
      setImmediate(() => {
        this.callback(
            opt_callback,
            new Error(
                'Must pass in a stream containing the user refresh token.'));
      });
      return;
    }
    let s = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      s += chunk;
    });
    stream.on('end', () => {
      try {
        const data = JSON.parse(s);
        this.fromJSON(data, opt_callback);
      } catch (err) {
        this.callback(opt_callback, err);
      }
    });
  }
}
