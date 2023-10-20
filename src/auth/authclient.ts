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
import {Gaxios, GaxiosOptions, GaxiosPromise, GaxiosResponse} from 'gaxios';

import {DefaultTransporter, Transporter} from '../transporters';
import {Credentials} from './credentials';
import {Headers} from './oauth2client';
import {OriginalAndCamel, getOriginalOrCamel} from '../util';

/**
 * Base auth configurations (e.g. from JWT or `.json` files)
 */
export interface AuthJSONOptions {
  /**
   * The project ID corresponding to the current credentials if available.
   */
  project_id: string | null;

  /**
   * The quota project ID. The quota project can be used by client libraries for the billing purpose.
   * See {@link https://cloud.google.com/docs/quota Working with quotas}
   */
  quota_project_id: string;

  /**
   * The default service domain for a given Cloud universe
   */
  universe_domain: string;
}

/**
 * Base Auth Client configuration
 */
export type AuthClientOptions = Partial<
  OriginalAndCamel<AuthJSONOptions> & {
    credentials: Credentials;

    /**
     * A `Gaxios` or `Transporter` instance to use for `AuthClient` requests.
     */
    transporter: Gaxios | Transporter;

    /**
     * Provides default options to the transporter, such as {@link GaxiosOptions.agent `agent`} or
     *  {@link GaxiosOptions.retryConfig `retryConfig`}.
     */
    transporterOptions: GaxiosOptions;

    /**
     * The expiration threshold in milliseconds before forcing token refresh of
     * unexpired tokens.
     */
    eagerRefreshThresholdMillis: number;

    /**
     * Whether to attempt to refresh tokens on status 401/403 responses
     * even if an attempt is made to refresh the token preemptively based
     * on the expiry_date.
     */
    forceRefreshOnFailure: boolean;
  }
>;

/**
 * The default cloud universe
 *
 * @see {@link AuthJSONOptions.universe_domain}
 */
export const DEFAULT_UNIVERSE = 'googleapis.com';

/**
 * The default {@link AuthClientOptions.eagerRefreshThresholdMillis}
 */
export const DEFAULT_EAGER_REFRESH_THRESHOLD_MILLIS = 5 * 60 * 1000;

/**
 * Defines the root interface for all clients that generate credentials
 * for calling Google APIs. All clients should implement this interface.
 */
export interface CredentialsClient {
  projectId?: AuthClientOptions['projectId'];
  eagerRefreshThresholdMillis: NonNullable<
    AuthClientOptions['eagerRefreshThresholdMillis']
  >;
  forceRefreshOnFailure: NonNullable<
    AuthClientOptions['forceRefreshOnFailure']
  >;

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

export abstract class AuthClient
  extends EventEmitter
  implements CredentialsClient
{
  projectId?: string | null;
  /**
   * The quota project ID. The quota project can be used by client libraries for the billing purpose.
   * See {@link https://cloud.google.com/docs/quota Working with quotas}
   */
  quotaProjectId?: string;
  transporter: Transporter;
  credentials: Credentials = {};
  eagerRefreshThresholdMillis = DEFAULT_EAGER_REFRESH_THRESHOLD_MILLIS;
  forceRefreshOnFailure = false;
  universeDomain = DEFAULT_UNIVERSE;

  constructor(opts: AuthClientOptions = {}) {
    super();

    // Shared auth options
    this.projectId = getOriginalOrCamel(opts, 'project_id') ?? null;
    this.quotaProjectId = getOriginalOrCamel(opts, 'quota_project_id');
    this.credentials = getOriginalOrCamel(opts, 'credentials') ?? {};
    this.universeDomain =
      getOriginalOrCamel(opts, 'universe_domain') ?? DEFAULT_UNIVERSE;

    // Shared client options
    this.transporter = opts.transporter ?? new DefaultTransporter();

    if (opts.transporterOptions) {
      this.transporter.defaults = opts.transporterOptions;
    }

    if (opts.eagerRefreshThresholdMillis) {
      this.eagerRefreshThresholdMillis = opts.eagerRefreshThresholdMillis;
    }

    this.forceRefreshOnFailure = opts.forceRefreshOnFailure ?? false;
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
