// Copyright 2019 Google LLC
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
  Gaxios,
  GaxiosError,
  GaxiosOptions,
  GaxiosPromise,
  GaxiosResponse,
} from 'gaxios';
import {validate} from './options';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../../package.json');

const PRODUCT_NAME = 'google-api-nodejs-client';

export interface Transporter {
  defaults?: GaxiosOptions;
  request<T>(opts: GaxiosOptions): GaxiosPromise<T>;
}

export interface BodyResponseCallback<T> {
  // The `body` object is a truly dynamic type.  It must be `any`.
  (err: Error | null, res?: GaxiosResponse<T> | null): void;
}

export interface RequestError extends GaxiosError {
  errors: Error[];
}

export class DefaultTransporter implements Transporter {
  /**
   * Default user agent.
   */
  static readonly USER_AGENT = `${PRODUCT_NAME}/${pkg.version}`;

  /**
   * A configurable, replacable `Gaxios` instance.
   */
  instance = new Gaxios();

  /**
   * Configures request options before making a request.
   * @param opts GaxiosOptions options.
   * @return Configured options.
   */
  configure(opts: GaxiosOptions = {}): GaxiosOptions {
    opts.headers = opts.headers || {};
    if (typeof window === 'undefined') {
      // set transporter user agent if not in browser
      const uaValue: string = opts.headers['User-Agent'];
      if (!uaValue) {
        opts.headers['User-Agent'] = DefaultTransporter.USER_AGENT;
      } else if (!uaValue.includes(`${PRODUCT_NAME}/`)) {
        opts.headers[
          'User-Agent'
        ] = `${uaValue} ${DefaultTransporter.USER_AGENT}`;
      }
      // track google-auth-library-nodejs version:
      if (!opts.headers['x-goog-api-client']) {
        const nodeVersion = process.version.replace(/^v/, '');
        opts.headers['x-goog-api-client'] = `gl-node/${nodeVersion}`;
      }
    }
    return opts;
  }

  /**
   * Makes a request using Gaxios with given options.
   * @param opts GaxiosOptions options.
   * @param callback optional callback that contains GaxiosResponse object.
   * @return GaxiosPromise, assuming no callback is passed.
   */
  request<T>(opts: GaxiosOptions): GaxiosPromise<T> {
    // ensure the user isn't passing in request-style options
    opts = this.configure(opts);
    validate(opts);
    return this.instance.request<T>(opts).catch(e => {
      throw this.processError(e);
    });
  }

  get defaults() {
    return this.instance.defaults;
  }

  set defaults(opts: GaxiosOptions) {
    this.instance.defaults = opts;
  }

  /**
   * Changes the error to include details from the body.
   */
  private processError(e: GaxiosError): RequestError {
    const res = e.response;
    const err = e as RequestError;
    const body = res ? res.data : null;
    if (res && body && body.error && res.status !== 200) {
      if (typeof body.error === 'string') {
        err.message = body.error;
        err.status = res.status;
      } else if (Array.isArray(body.error.errors)) {
        err.message = body.error.errors
          .map((err2: Error) => err2.message)
          .join('\n');
        err.code = body.error.code;
        err.errors = body.error.errors;
      } else {
        err.message = body.error.message;
        err.code = body.error.code;
      }
    } else if (res && res.status >= 400) {
      // Consider all 4xx and 5xx responses errors.
      err.message = body;
      err.status = res.status;
    }
    return err;
  }
}
