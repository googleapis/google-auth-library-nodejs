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

import {AxiosError, AxiosPromise, AxiosRequestConfig} from 'axios';

import {RequestError} from './../transporters';
import {GetTokenResponse, OAuth2Client} from './oauth2client';

export interface Token {
  expires_in: number;
  expiry_date: number;
}

export class Compute extends OAuth2Client {
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
    // Start with an expired refresh token, which will automatically be
    // refreshed before the first API call is made.
    this.credentials = {expiry_date: 1, refresh_token: 'compute-placeholder'};
  }

  /**
   * Indicates whether the credential requires scopes to be created by calling
   * createdScoped before use.
   * @return {object} The cloned instance.
   */
  createScopedRequired() {
    // On compute engine, scopes are specified at the compute instance's
    // creation time, and cannot be changed. For this reason, always return
    // false.
    return false;
  }

  /**
   * Refreshes the access token.
   * @param {object=} ignored_
   * @param {function=} callback Optional callback.
   */
  protected async refreshToken(refreshToken?: string|
                               null): Promise<GetTokenResponse> {
    try {
      const url = this.opts.tokenUrl || Compute._GOOGLE_OAUTH2_TOKEN_URL;
      // request for new token
      const res = await this.transporter.request({url});
      const tokens = res.data as Token;
      if (tokens && tokens.expires_in) {
        tokens.expiry_date =
            ((new Date()).getTime() + (tokens.expires_in * 1000));
        delete tokens.expires_in;
      }
      return {tokens, res};
    } catch (e) {
      e.message = 'Could not refresh access token.';
      throw e;
    }
  }


  protected requestAsync<T>(opts: AxiosRequestConfig, retry = false):
      AxiosPromise<T> {
    return super.requestAsync<T>(opts, retry).catch(e => {
      const res = (e as AxiosError).response;
      if (res && res.status) {
        let helpfulMessage = null;
        if (res.status === 403) {
          helpfulMessage =
              'A Forbidden error was returned while attempting to retrieve an access ' +
              'token for the Compute Engine built-in service account. This may be because the Compute ' +
              'Engine instance does not have the correct permission scopes specified.';
        } else if (res.status === 404) {
          helpfulMessage =
              'A Not Found error was returned while attempting to retrieve an access' +
              'token for the Compute Engine built-in service account. This may be because the Compute ' +
              'Engine instance does not have any permission scopes specified.';
        }
        if (helpfulMessage) {
          if (e && e.message && !retry) {
            helpfulMessage += ' ' + e.message;
          }
          if (e) {
            e.message = helpfulMessage;
          } else {
            e = new Error(helpfulMessage);
            (e as RequestError).code = res.status.toString();
          }
        }
      }
      throw e;
    });
  }
}
