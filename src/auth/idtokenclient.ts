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

import {Credentials} from './credentials';
import {
  Headers,
  OAuth2Client,
  OAuth2ClientOptions,
  RequestMetadataResponse,
} from './oauth2client';

export interface IdTokenOptions extends OAuth2ClientOptions {
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

export class IdTokenClient extends OAuth2Client {
  targetAudience: string;
  idTokenProvider: IdTokenProvider;

  /**
   * Google ID Token client
   *
   * Retrieve ID token from the metadata server.
   * See: https://cloud.google.com/docs/authentication/get-id-token#metadata-server
   */
  constructor(options: IdTokenOptions) {
    super(options);
    this.targetAudience = options.targetAudience;
    this.idTokenProvider = options.idTokenProvider;
  }

  protected async getRequestMetadataAsync(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    url?: string | null
  ): Promise<RequestMetadataResponse> {
    if (
      !this.credentials.id_token ||
      !this.credentials.expiry_date ||
      this.isTokenExpiring()
    ) {
      const idToken = await this.idTokenProvider.fetchIdToken(
        this.targetAudience
      );
      this.credentials = {
        id_token: idToken,
        expiry_date: this.getIdTokenExpiryDate(idToken),
      } as Credentials;
    }

    const headers: Headers = {
      Authorization: 'Bearer ' + this.credentials.id_token,
    };
    return {headers};
  }

  private getIdTokenExpiryDate(idToken: string): number | void {
    const payloadB64 = idToken.split('.')[1];
    if (payloadB64) {
      const payload = JSON.parse(
        Buffer.from(payloadB64, 'base64').toString('ascii')
      );
      return payload.exp * 1000;
    }
  }
}
