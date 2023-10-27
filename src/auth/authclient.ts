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
import {pkg, OriginalAndCamel, originalOrCamelOptions} from '../util';

/**
 * Support `instanceof` operator for `AuthClient`s in different versions of this library.
 *
 * @see {@link AuthClient[Symbol.hasInstance]}
 */
export const AUTH_CLIENT_SYMBOL = Symbol.for(`${pkg.name}-authclient`);

/**
 * Base auth configurations (e.g. from JWT or `.json` files) with conventional
 * camelCased options.
 *
 * @privateRemarks
 *
 * This interface is purposely not exported so that it can be removed once
 * {@link https://github.com/microsoft/TypeScript/issues/50715} has been
 * resolved. Then, we can use {@link OriginalAndCamel} to shrink this interface.
 *
 * Tracking: {@link https://github.com/googleapis/google-auth-library-nodejs/issues/1686}
 */
interface AuthJSONOptions {
  /**
   * The project ID corresponding to the current credentials if available.
   */
  project_id: string | null;
  /**
   * An alias for {@link AuthJSONOptions.project_id `project_id`}.
   */
  projectId: AuthJSONOptions['project_id'];

  /**
   * The quota project ID. The quota project can be used by client libraries for the billing purpose.
   * See {@link https://cloud.google.com/docs/quota Working with quotas}
   */
  quota_project_id: string;

  /**
   * An alias for {@link AuthJSONOptions.quota_project_id `quota_project_id`}.
   */
  quotaProjectId: AuthJSONOptions['quota_project_id'];

  /**
   * The default service domain for a given Cloud universe.
   */
  universe_domain: string;

  /**
   * An alias for {@link AuthJSONOptions.universe_domain `universe_domain`}.
   */
  universeDomain: AuthJSONOptions['universe_domain'];
}

/**
 * Base `AuthClient` configuration.
 *
 * The camelCased options are aliases of the snake_cased options, supporting both
 * JSON API and JS conventions.
 */
export interface AuthClientOptions
  extends Partial<OriginalAndCamel<AuthJSONOptions>> {
  credentials?: Credentials;

  /**
   * A `Gaxios` or `Transporter` instance to use for `AuthClient` requests.
   */
  transporter?: Gaxios | Transporter;

  /**
   * Provides default options to the transporter, such as {@link GaxiosOptions.agent `agent`} or
   *  {@link GaxiosOptions.retryConfig `retryConfig`}.
   */
  transporterOptions?: GaxiosOptions;

  /**
   * The expiration threshold in milliseconds before forcing token refresh of
   * unexpired tokens.
   */
  eagerRefreshThresholdMillis?: number;

  /**
   * Whether to attempt to refresh tokens on status 401/403 responses
   * even if an attempt is made to refresh the token preemptively based
   * on the expiry_date.
   */
  forceRefreshOnFailure?: boolean;
}

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

/**
 * A capabilities-based, backwards-compatible interface for {@link AuthClient}.
 * Library maintainers should use this interface when library maintainers want
 * an `AuthClient` from a non-specific `google-auth-library` version.
 * This greatly improves user experience where customers have multiple versions
 * of `google-auth-library` thus instances of `AuthClient != AuthClient` (e.g.
 * v8 vs v9).
 *
 * @see {@link AuthClient}.
 * @see {@link AuthClient[Symbol.hasInstance]}.
 *
 * @see {@link https://github.com/googleapis/google-auth-library-nodejs/issues/1402} for background.
 *
 * @example
 * ```ts
 * const authClient: AuthClient | AuthClientLike = {};
 *
 * // Assert `authClient` a valid `AuthClient`
 * assert(authClient instanceof AuthClient);
 * ```
 */
export interface AuthClientLike {
  setCredentials(credentials: Credentials): void;
  request: (opts: {}) => Promise<{}>;
}

export abstract class AuthClient
  extends EventEmitter
  implements CredentialsClient, AuthClientLike
{
  projectId?: string | null;
  /**
   * Support `instanceof` operator for `AuthClient`s in different versions of this library.
   *
   * @see {@link AuthClient[Symbol.hasInstance]}
   */
  [AUTH_CLIENT_SYMBOL] = pkg.version;

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

    const options = originalOrCamelOptions(opts);

    // Shared auth options
    this.projectId = options.get('project_id') ?? null;
    this.quotaProjectId = options.get('quota_project_id');
    this.credentials = options.get('credentials') ?? {};
    this.universeDomain = options.get('universe_domain') ?? DEFAULT_UNIVERSE;

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
   * Support `instanceof` operator for `AuthClient`s in different versions of this library.
   *
   * @see {@link AUTH_CLIENT_SYMBOL}
   */
  static [Symbol.hasInstance](obj: {}): boolean {
    if (this === AuthClient) {
      return obj && AUTH_CLIENT_SYMBOL in obj;
    } else {
      // must be a child of this class, use the original method.
      return Function.prototype[Symbol.hasInstance].call(this, obj);
    }
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
