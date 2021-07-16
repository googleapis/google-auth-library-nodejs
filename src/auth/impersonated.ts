/**
 * Copyright 2019 Google LLC
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

import {GaxiosOptions, GaxiosPromise} from 'gaxios';
import {
  GetTokenResponse,
  Headers,
  OAuth2Client,
  RefreshOptions,
  RequestMetadataResponse,
} from './oauth2client';

export interface ImpersonatedOptions extends RefreshOptions {
  sourceClient?: OAuth2Client;
  targetPrincipal?: string;
  targetScopes?: string[];
  delegates?: string[];
  lifetime?: number | 3600;
  endpoint?: string | 'https://iamcredentials.googleapis.com';
}

export interface TokenResponse {
  accessToken: string;
  expireTime: string;
}

export class Impersonated extends OAuth2Client {
  private sourceClient: OAuth2Client;
  private targetPrincipal: string;
  private targetScopes: string[];
  private delegates: string[];
  private lifetime: number;
  private endpoint: string;

  /**
   * Impersonated service account credentials.
   *
   * Create a new access token by impersonating another service account.
   *
   * Impersonated Credentials allowing credentials issued to a user or
   * service account to impersonate another. The source project using
   * Impersonated Credentials must enable the "IAMCredentials" API.
   * Also, the target service account must grant the orginating principal
   * the "Service Account Token Creator" IAM role.
   *
   * @param credentials the service account email address.
   * @param sourceClient the source credential used as to acquire the
   * impersonated credentials
   * @param targetPrincipal the service account to impersonate.
   * @param delegates the chained list of delegates required to grant the
   *  final access_token. If set, the sequence of identities must have
   * "Service Account Token Creator" capability granted to the preceding
   * identity. For example, if set to [serviceAccountB, serviceAccountC],
   * the sourceCredential must have the Token Creator role on serviceAccountB.
   * serviceAccountB must have the Token Creator on serviceAccountC.
   * Finally, C must have Token Creator on target_principal.
   * If left unset, sourceCredential must have that role on targetPrincipal.
   * @param targetScopes scopes to request during the authorization grant.
   * @param lifetime number of seconds the delegated credential should be
   * valid for (up to 3600).
   * @param endpoint api endpoint override.
   */
  constructor(options: ImpersonatedOptions = {}) {
    super(options);
    this.credentials = {
      expiry_date: 1,
      refresh_token: 'impersonated-placeholder',
    };
    this.sourceClient = options.sourceClient || new OAuth2Client();
    this.targetPrincipal = options.targetPrincipal || '';
    this.delegates = options.delegates || [];
    this.targetScopes = options.targetScopes || [];
    this.lifetime = options.lifetime || 3600;
    this.endpoint = options.endpoint || 'https://iamcredentials.googleapis.com';
  }

  /**
   * Refreshes the access token.
   * @param refreshToken Unused parameter
   */
  protected async refreshToken(
    refreshToken?: string | null
  ): Promise<GetTokenResponse> {
    if (this.isTokenExpiring()) {
      try {
        await this.sourceClient.getAccessToken();
        const name = 'projects/-/serviceAccounts/' + this.targetPrincipal;
        const u = `${this.endpoint}/v1/${name}:generateAccessToken`;
        const body = {
          delegates: this.delegates,
          scope: this.targetScopes,
          lifetime: this.lifetime + 's',
        };
        const res = await this.sourceClient.request({
          url: u,
          data: body,
          method: 'POST',
        });
        const tokenResponse = res.data as TokenResponse;
        this.credentials.access_token = tokenResponse.accessToken;
        this.credentials.expiry_date =
          Date.parse(tokenResponse.expireTime) / 1000;
        return {
          tokens: this.credentials,
          res,
        };
      } catch (error) {
        const status = error?.response?.data?.error?.status;
        const message = error?.response?.data?.error?.message;
        if (status && message) {
          throw new Error(`${status}: unable to impersonate: ${message}`);
        } else {
          throw new Error(`unable to impersonate: ${error}`);
        }
      }
    }
    return {tokens: this.credentials, res: null};
  }

  protected requestAsync<T>(
    opts: GaxiosOptions,
    retry = false
  ): GaxiosPromise<T> {
    return super.requestAsync<T>(opts, retry);
  }

  /**
   * Get a non-expired access token, after refreshing if necessary.
   *
   * @param url The URI being authorized.
   * @returns An object that includes the authorization header.
   */
  async getRequestHeaders(): Promise<Headers> {
    const res = await this.getRequestMetadataAsync();
    return res.headers;
  }

  protected async getRequestMetadataAsync(
    url?: string | null
  ): Promise<RequestMetadataResponse> {
    if (this.isTokenExpiring()) {
      await this.getAccessToken();
    }

    const headers = {
      Authorization: 'Bearer ' + this.credentials.access_token,
    };
    return {headers};
  }
}
