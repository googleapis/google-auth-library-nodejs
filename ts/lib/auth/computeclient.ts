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

import Auth2Client from './oauth2client';

export default class Compute extends Auth2Client {

  /**
   * Google Compute Engine metadata server token endpoint.
   */
  protected static readonly _GOOGLE_OAUTH2_TOKEN_URL =
    'http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token';

  /**
   * Google Compute Engine service account credentials.
   *
   * Retrieve access token from the metadata server.
   * See: https://developers.google.com/compute/docs/authentication
   */
  constructor() {
    super();
    // Start with an expired refresh token, which will automatically be refreshed
    // before the first API call is made.
    this.credentials = {
      expiry_date: 1,
      refresh_token: 'compute-placeholder'
    };
  }

  /**
   * Indicates whether the credential requires scopes to be created by calling createdScoped before
   * use.
   * @return {object} The cloned instance.
   */
  public createScopedRequired() {
    // On compute engine, scopes are specified at the compute instance's creation time,
    // and cannot be changed. For this reason, always return false.
    return false;
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored_
   * @param {function=} opt_callback Optional callback.
   */
  protected refreshToken(ignored, callback?) {
    const uri = this._opts.tokenUrl || Compute._GOOGLE_OAUTH2_TOKEN_URL;
    // request for new token
    return this.transporter.request({
      method: 'GET',
      uri: uri,
      json: true
    }, (err, tokens, response) => {
      if (!err && tokens && tokens.expires_in) {
        tokens.expiry_date = ((new Date()).getTime() + (tokens.expires_in * 1000));
        delete tokens.expires_in;
      }
      if (callback) {
        callback(err, tokens, response);
      }
    });
  }

  /**
   * Inserts a helpful error message guiding the user toward fixing common auth issues.
   * @param {object} err Error result.
   * @param {object} result The result.
   * @param {object} response The HTTP response.
   * @param {Function} callback The callback.
   */
  protected postRequest(err, result, response, callback) {
    if (response && response.statusCode) {
      let helpfulMessage = null;
      if (response.statusCode === 403) {
        helpfulMessage = 'A Forbidden error was returned while attempting to retrieve an access ' +
          'token for the Compute Engine built-in service account. This may be because the Compute ' +
          'Engine instance does not have the correct permission scopes specified.';
      } else if (response.statusCode === 404) {
        helpfulMessage = 'A Not Found error was returned while attempting to retrieve an access' +
          'token for the Compute Engine built-in service account. This may be because the Compute ' +
          'Engine instance does not have any permission scopes specified.';
      }
      if (helpfulMessage) {
        if (err && err.message) {
          helpfulMessage += ' ' + err.message;
        }

        if (err) {
          err.message = helpfulMessage;
        } else {
          err = new Error(helpfulMessage);
          err.code = response.statusCode;
        }
      }
    }
    callback(err, result, response);
  }
}
