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

import {GaxiosOptions, GaxiosResponse} from 'gaxios';
import * as querystring from 'querystring';

import {DefaultTransporter} from '../transporters';
import {Headers} from './oauth2client';
import {
  ClientAuthentication,
  OAuthClientAuthHandler,
  OAuthErrorResponse,
  getErrorFromOAuthErrorResponse,
} from './oauth2common';

/**
 * Defines the interface needed to initialize an StsCredentials instance.
 * The interface does not directly map to the spec and instead is converted
 * to be compliant with the JavaScript style guide. This is because this is
 * instantiated internally.
 * StsCredentials implement the OAuth 2.0 token exchange based on
 * https://tools.ietf.org/html/rfc8693.
 * Request options are defined in
 * https://tools.ietf.org/html/rfc8693#section-2.1
 */
export interface StsCredentialsOptions {
  grantType: string;
  resource?: string;
  audience?: string;
  scope?: string[];
  requestedTokenType?: string;
  subjectToken: string;
  subjectTokenType: string;
  actingParty?: {
    actorToken: string;
    actorTokenType: string;
  };
}

/**
 * Defines the standard request options as defined by the OAuth token
 * exchange spec: https://tools.ietf.org/html/rfc8693#section-2.1
 */
interface StsRequestOptions {
  grant_type: string;
  resource?: string;
  audience?: string;
  scope?: string;
  requested_token_type?: string;
  subject_token: string;
  subject_token_type: string;
  actor_token?: string;
  actor_token_type?: string;
  client_id?: string;
  client_secret?: string;
  [key: string]: string | undefined;
}

/**
 * Defines the OAuth 2.0 token exchange successful response based on
 * https://tools.ietf.org/html/rfc8693#section-2.2.1
 */
export interface StsSuccessfulResponse {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  res?: GaxiosResponse | null;
}

/**
 * Implements the OAuth 2.0 token exchange based on
 * https://tools.ietf.org/html/rfc8693
 */
export class StsCredentials extends OAuthClientAuthHandler {
  private transporter: DefaultTransporter;

  /**
   * Initializes an STS credentials instance.
   * @param tokenExchangeEndpoint The token exchange endpoint.
   * @param clientAuthentication The client authentication credentials if
   *   available.
   */
  constructor(
    private readonly tokenExchangeEndpoint: string,
    clientAuthentication?: ClientAuthentication
  ) {
    super(clientAuthentication);
    this.transporter = new DefaultTransporter();
  }

  /**
   * Exchanges the provided token for another type of token based on the
   * rfc8693 spec.
   * @param stsCredentialsOptions The token exchange options used to populate
   *   the token exchange request.
   * @param additionalHeaders Optional additional headers to pass along the
   *   request.
   * @param options Optional additional GCP-specific non-spec defined options
   *   to send with the request.
   *   Example: `&options=${encodeUriComponent(JSON.stringified(options))}`
   * @return A promise that resolves with the token exchange response containing
   *   the requested token and its expiration time.
   */
  async exchangeToken(
    stsCredentialsOptions: StsCredentialsOptions,
    additionalHeaders?: Headers,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    options?: {[key: string]: any}
  ): Promise<StsSuccessfulResponse> {
    const values: StsRequestOptions = {
      grant_type: stsCredentialsOptions.grantType,
      resource: stsCredentialsOptions.resource,
      audience: stsCredentialsOptions.audience,
      scope: stsCredentialsOptions.scope?.join(' '),
      requested_token_type: stsCredentialsOptions.requestedTokenType,
      subject_token: stsCredentialsOptions.subjectToken,
      subject_token_type: stsCredentialsOptions.subjectTokenType,
      actor_token: stsCredentialsOptions.actingParty?.actorToken,
      actor_token_type: stsCredentialsOptions.actingParty?.actorTokenType,
      // Non-standard GCP-specific options.
      options: options && JSON.stringify(options),
    };
    // Remove undefined fields.
    Object.keys(values).forEach(key => {
      if (typeof values[key] === 'undefined') {
        delete values[key];
      }
    });

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    // Inject additional STS headers if available.
    Object.assign(headers, additionalHeaders || {});

    const opts: GaxiosOptions = {
      url: this.tokenExchangeEndpoint,
      method: 'POST',
      headers,
      data: querystring.stringify(values),
      responseType: 'json',
    };
    // Apply OAuth client authentication.
    this.applyClientAuthenticationOptions(opts);

    try {
      const response = await this.transporter.request<StsSuccessfulResponse>(
        opts
      );
      // Successful response.
      const stsSuccessfulResponse = response.data;
      stsSuccessfulResponse.res = response;
      return stsSuccessfulResponse;
    } catch (error) {
      // Translate error to OAuthError.
      if (error.response) {
        throw getErrorFromOAuthErrorResponse(
          error.response.data as OAuthErrorResponse
        );
      }
      // Request could fail before the server responds.
      throw error;
    }
  }
}
