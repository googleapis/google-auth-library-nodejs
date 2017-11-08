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
import * as stream from 'stream';

import {BodyResponseCallback} from './../transporters';
import {OAuth2Client} from './oauth2client';

export class UserRefreshClient extends OAuth2Client {
  // TODO: refactor tests to make this private
  // In a future gts release, the _propertyName rule will be lifted.
  // This is also a hard one because `this.refreshToken` is a function.
  // tslint:disable-next-line
  public _refreshToken?: string;

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
    this._refreshToken = refreshToken;
  }

  // Executes the given callback if it is not null.
  private callback(c?: Function, err?: Error, res?: request.RequestResponse) {
    if (c) {
      c(err, res);
    }
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored
   * @param {function=} callback Optional callback.
   * @private
   */
  protected refreshToken(ignored: any, callback?: BodyResponseCallback):
      request.Request|void {
    return super.refreshToken(this._refreshToken, callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * options.
   * @param {object=} json The input object.
   * @param {function=} callback Optional callback.
   */
  public fromJSON(json: any, callback?: (err?: Error) => void) {
    if (!json) {
      this.callback(
          callback,
          new Error(
              'Must pass in a JSON object containing the user refresh token'));
      return;
    }
    if (json.type !== 'authorized_user') {
      this.callback(
          callback,
          new Error(
              'The incoming JSON object does not have the "authorized_user" type'));
      return;
    }
    if (!json.client_id) {
      this.callback(
          callback,
          new Error(
              'The incoming JSON object does not contain a client_id field'));
      return;
    }
    if (!json.client_secret) {
      this.callback(
          callback,
          new Error(
              'The incoming JSON object does not contain a client_secret field'));
      return;
    }
    if (!json.refresh_token) {
      this.callback(
          callback,
          new Error(
              'The incoming JSON object does not contain a refresh_token field'));
      return;
    }
    this.clientId = json.client_id;
    this.clientSecret = json.client_secret;
    this._refreshToken = json.refresh_token;
    this.credentials.refresh_token = json.refresh_token;
    this.callback(callback);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * stream.
   * @param {object=} inputStream The input stream.
   * @param {function=} callback Optional callback.
   */
  public fromStream(
      inputStream: stream.Readable, callback?: (err?: Error) => void) {
    if (!inputStream) {
      setImmediate(() => {
        this.callback(
            callback,
            new Error(
                'Must pass in a stream containing the user refresh token.'));
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
        this.callback(callback, err);
      }
    });
  }
}
