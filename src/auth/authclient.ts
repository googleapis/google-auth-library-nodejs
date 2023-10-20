// Copyright 2012 Google LLC
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

import {EventEmitter} from 'events';
import {GaxiosOptions, GaxiosPromise, GaxiosResponse} from 'gaxios';

import {DefaultTransporter, Transporter} from '../transporters';
import {Credentials} from './credentials';
import {Headers} from './oauth2client';

/**
 * Defines the root interface for all clients that generate credentials
 * for calling Google APIs. All clients should implement this interface.
 */
export interface CredentialsClient {
  /**
   * The project ID corresponding to the current credentials if available.
   */
  projectId?: string | null;

  /**
   * The expiration threshold in milliseconds before forcing token refresh.
   */
  eagerRefreshThresholdMillis: number;

  /**
   * Whether to force refresh on failure when making an authorization request.
   */
  forceRefreshOnFailure: boolean;

  /**
   * @return A promise that resolves with the current GCP access token
   *   response. If the current credential is expired, a new one is retrieved.
   */
  getAccessToken(): Promise<{
    token?: string | null;
    res?: GaxiosResponse | null;
  }>;

  /**
   * The main authentication interface. It takes an optional url which when
   * present is the endpoint being accessed, and returns a Promise which
   * resolves with authorization header fields.
   *
   * The result has the form:
   * { Authorization: 'Bearer <access_token_value>' }
   * @param url The URI being authorized.
   */
  getRequestHeaders(url?: string): Promise<Headers>;

  /**
   * Provides an alternative Gaxios request implementation with auth credentials
   */
  request<T>(opts: GaxiosOptions): GaxiosPromise<T>;

  /**
   * Sets the auth credentials.
   */
  setCredentials(credentials: Credentials): void;

  /**
   * Subscribes a listener to the tokens event triggered when a token is
   * generated.
   *
   * @param event The tokens event to subscribe to.
   * @param listener The listener that triggers on event trigger.
   * @return The current client instance.
   */
  on(event: 'tokens', listener: (tokens: Credentials) => void): this;
}

export declare interface AuthClient {
  on(event: 'tokens', listener: (tokens: Credentials) => void): this;
}

/**
 * A capabilities-based, backwards-compatible interface for {@link AuthClient}.
 * This is useful for projects where multiple versions of `google-auth-library`
 * may exist and thus instances of `AuthClient != AuthClient` (e.g. v8 vs v9).
 *
 * @see {@link AuthClient}.
 * @see {@link AuthClient.normalize} for the normalizing this to {@link AuthClient}.
 *
 * @see {@link https://github.com/googleapis/google-auth-library-nodejs/issues/1402} for background.
 */
export interface AuthClientLike {
  setCredentials(credentials: Credentials): void;
  request: (opts: {}) => Promise<{}>;
}

export abstract class AuthClient
  extends EventEmitter
  implements CredentialsClient, AuthClientLike
{
  /**
   * The quota project ID. The quota project can be used by client libraries for the billing purpose.
   * See {@link https://cloud.google.com/docs/quota Working with quotas}
   */
  quotaProjectId?: string;
  transporter: Transporter = new DefaultTransporter();
  credentials: Credentials = {};
  projectId?: string | null;
  eagerRefreshThresholdMillis = 5 * 60 * 1000;
  forceRefreshOnFailure = false;

  /**
   * Different versions of `AuthClient` may use this method to ensure
   * the provided `AuthClientLike` has the appropriate capabilities
   * required for its respective version.
   *
   * @see {@link AuthClientLike}'s description and background.
   *
   * @param authClient an {@link AuthClientLike} instance to normalize.
   * @returns a normalized {@link AuthClient} instance.
   */
  static normalize<T extends AuthClient = AuthClient>(
    authClient: AuthClientLike | T
  ): T {
    return authClient as T;
  }

  /**
   * Provides an alternative Gaxios request implementation with auth credentials
   */
  abstract request<T>(opts: GaxiosOptions): GaxiosPromise<T>;

  /**
   * The main authentication interface. It takes an optional url which when
   * present is the endpoint being accessed, and returns a Promise which
   * resolves with authorization header fields.
   *
   * The result has the form:
   * { Authorization: 'Bearer <access_token_value>' }
   * @param url The URI being authorized.
   */
  abstract getRequestHeaders(url?: string): Promise<Headers>;

  /**
   * @return A promise that resolves with the current GCP access token
   *   response. If the current credential is expired, a new one is retrieved.
   */
  abstract getAccessToken(): Promise<{
    token?: string | null;
    res?: GaxiosResponse | null;
  }>;

  /**
   * Sets the auth credentials.
   */
  setCredentials(credentials: Credentials) {
    this.credentials = credentials;
  }

  /**
   * Append additional headers, e.g., x-goog-user-project, shared across the
   * classes inheriting AuthClient. This method should be used by any method
   * that overrides getRequestMetadataAsync(), which is a shared helper for
   * setting request information in both gRPC and HTTP API calls.
   *
   * @param headers object to append additional headers to.
   */
  protected addSharedMetadataHeaders(headers: Headers): Headers {
    // quota_project_id, stored in application_default_credentials.json, is set in
    // the x-goog-user-project header, to indicate an alternate account for
    // billing and quota:
    if (
      !headers['x-goog-user-project'] && // don't override a value the user sets.
      this.quotaProjectId
    ) {
      headers['x-goog-user-project'] = this.quotaProjectId;
    }
    return headers;
  }
}
