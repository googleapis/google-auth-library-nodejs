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

import {GaxiosError, GaxiosOptions, GaxiosPromise} from 'gaxios';
import * as gcpMetadata from 'gcp-metadata';
import * as messages from '../messages';
import {CredentialRequest, Credentials} from './credentials';
import {GetTokenResponse, OAuth2Client, RefreshOptions} from './oauth2client';

export interface ComputeOptions extends RefreshOptions {
  /**
   * The service account email to use, or 'default'. A Compute Engine instance
   * may have multiple service accounts.
   */
  serviceAccountEmail?: string;
}

export class Compute extends OAuth2Client {
  private serviceAccountEmail: string;

  /**
   * Google Compute Engine service account credentials.
   *
   * Retrieve access token from the metadata server.
   * See: https://developers.google.com/compute/docs/authentication
   */
  constructor(options: ComputeOptions = {}) {
    super(options);
    // Start with an expired refresh token, which will automatically be
    // refreshed before the first API call is made.
    this.credentials = {expiry_date: 1, refresh_token: 'compute-placeholder'};
    this.serviceAccountEmail = options.serviceAccountEmail || 'default';
  }

  /**
   * Indicates whether the credential requires scopes to be created by calling
   * createdScoped before use.
   * @deprecated
   * @return Boolean indicating if scope is required.
   */
  createScopedRequired() {
    // On compute engine, scopes are specified at the compute instance's
    // creation time, and cannot be changed. For this reason, always return
    // false.
    messages.warn(messages.COMPUTE_CREATE_SCOPED_DEPRECATED);
    return false;
  }

  /**
   * Refreshes the access token.
   * @param refreshToken Unused parameter
   */
  protected async refreshTokenNoCache(refreshToken?: string|
                                      null): Promise<GetTokenResponse> {
    const tokenPath = `service-accounts/${this.serviceAccountEmail}/token`;
    let data: CredentialRequest;
    try {
      data = await gcpMetadata.instance(tokenPath);
    } catch (e) {
      e.message = `Could not refresh access token: ${e.message}`;
      throw e;
    }
    const tokens = data as Credentials;
    if (data && data.expires_in) {
      tokens.expiry_date = ((new Date()).getTime() + (data.expires_in * 1000));
      delete (tokens as CredentialRequest).expires_in;
    }
    this.emit('tokens', tokens);
    return {tokens, res: null};
  }

  protected requestAsync<T>(opts: GaxiosOptions, retry = false):
      GaxiosPromise<T> {
    return super.requestAsync<T>(opts, retry).catch(e => {
      const res = (e as GaxiosError).response;
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
            (e as NodeJS.ErrnoException).code = res.status.toString();
          }
        }
      }
      throw e;
    });
  }
}
