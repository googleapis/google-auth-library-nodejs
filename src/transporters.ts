/**
 * Copyright 2012 Google Inc. All Rights Reserved.
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

import axios, {AxiosError, AxiosPromise, AxiosRequestConfig, AxiosResponse} from 'axios';

// tslint:disable-next-line no-var-requires
const pkg = require('../../package.json');

export interface Transporter {
  request(opts: AxiosRequestConfig): AxiosPromise;
  request(opts: AxiosRequestConfig, callback?: BodyResponseCallback): void;
  request(opts: AxiosRequestConfig, callback?: BodyResponseCallback):
      AxiosPromise|void;
}

export interface BodyResponseCallback {
  // The `body` object is a truly dynamic type.  It must be `any`.
  // tslint:disable-next-line no-any
  (err: Error|null, body?: any, res?: AxiosResponse|null): void;
}

export interface RequestError extends AxiosError { errors: Error[]; }

export class DefaultTransporter {
  /**
   * Default user agent.
   */
  static readonly USER_AGENT = 'google-api-nodejs-client/' + pkg.version;

  /**
   * Configures request options before making a request.
   * @param {object} opts Options to configure.
   * @return {object} Configured options.
   */
  configure(opts: AxiosRequestConfig = {}): AxiosRequestConfig {
    // set transporter user agent
    if (!opts.headers) opts.headers = {};
    if (!opts.headers['User-Agent']) {
      opts.headers['User-Agent'] = DefaultTransporter.USER_AGENT;
    } else if (
        opts.headers['User-Agent'].indexOf(DefaultTransporter.USER_AGENT) ===
        -1) {
      opts.headers['User-Agent'] =
          opts.headers['User-Agent'] + ' ' + DefaultTransporter.USER_AGENT;
    }
    return opts;
  }

  /**
   * Makes a request with given options and invokes callback.
   * @param {object} opts Options.
   * @param {Function=} callback Optional callback.
   * @return {Request} Request object
   */
  request(opts: AxiosRequestConfig): AxiosPromise;
  request(opts: AxiosRequestConfig, callback?: BodyResponseCallback): void;
  request(opts: AxiosRequestConfig, callback?: BodyResponseCallback):
      AxiosPromise|void {
    opts = this.configure(opts);
    if (callback) {
      axios(opts)
          .then(r => {
            callback(null, r);
            return;
          })
          .catch(e => {
            callback(this.processError(e));
          });
    } else {
      return axios(opts).catch(e => {
        throw this.processError(e);
      });
    }
  }

  /**
   * Wraps the response callback.
   * @param {Function=} callback Optional callback.
   * @return {Function} Wrapped callback function.
   * @private
   */
  private processError(e: AxiosError): RequestError {
    const res = e.response;
    const err = e as RequestError;
    const body = res ? res.data : null;
    if (res && body && body.error && res.status !== 200) {
      if (typeof body.error === 'string') {
        err.message = body.error;
        err.code = res.status.toString();
      } else if (Array.isArray(body.error.errors)) {
        err.message =
            body.error.errors.map((err2: Error) => err2.message).join('\n');
        err.code = body.error.code;
        err.errors = body.error.errors;
      } else {
        err.message = body.error.message;
        err.code = body.error.code || res.status;
      }
    } else if (res && res.status >= 400) {
      // Consider all 4xx and 5xx responses errors.
      err.message = body;
      err.code = res.status.toString();
    }
    return err;
  }
}
