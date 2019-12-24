// Copyright 2020 Google LLC
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


import {
  GaxiosError,
  GaxiosOptions,
  GaxiosPromise,
  GaxiosResponse,
} from 'gaxios';

import {BodyResponseCallback} from '../transporters';

import {AuthClient} from './authclient';
import {OAuth2Client} from './oauth2client';

export interface IdTokenOptions {
  /**
   * The client to make the request to fetch an ID token.
   */
  idTokenProvider: IdTokenProvider;

  /**
   * The audience to use when requesting an ID token.
   */
  targetAudience: string;
}

export interface IdTokenProvider {
  fetchIdToken: (targetAudience: string) => Promise<string>;
}

export class IdTokenClient extends AuthClient {
  targetAudience: string;
  idTokenProvider: IdTokenProvider;

  /**
   * Google ID Token client
   *
   * Retrieve access token from the metadata server.
   * See: https://developers.google.com/compute/docs/authentication
   */
  constructor(options: IdTokenOptions) {
    super();
    this.targetAudience = options.targetAudience;
    this.idTokenProvider = options.idTokenProvider;
  }

  /**
   * Provides a request implementation with OAuth 2.0 flow. If credentials have
   * a refresh_token, in cases of HTTP 401 and 403 responses, it automatically
   * asks for a new access token and replays the unsuccessful request.
   * @param opts Request options.
   * @param callback callback.
   * @return Request object
   */
  request<T>(opts: GaxiosOptions): GaxiosPromise<T>;
  request<T>(opts: GaxiosOptions, callback: BodyResponseCallback<T>): void;
  request<T>(
    opts: GaxiosOptions,
    callback?: BodyResponseCallback<T>
  ): GaxiosPromise<T> | void {
    if (callback) {
      this.requestAsync<T>(opts).then(
        r => callback(null, r),
        e => {
          return callback(e, e.response);
        }
      );
    } else {
      return this.requestAsync<T>(opts);
    }
  }

  protected async requestAsync<T>(
    opts: GaxiosOptions,
    retry = false
  ): Promise<GaxiosResponse<T>> {
    let r2: GaxiosResponse;

    const idToken = await this.idTokenProvider.fetchIdToken(this.targetAudience);

    opts.headers = opts.headers || {};
    opts.headers.Authorization = `Bearer ${idToken}`;

    r2 = await this.transporter.request<T>(opts);

    return r2;
  }
}
