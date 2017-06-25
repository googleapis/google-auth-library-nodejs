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

import * as request from 'request';

// tslint:disable-next-line
const pkg = require('../package.json');

export interface Transporter {
  request(opts: any, opt_callback: RequestCallback): any;
}

export interface RequestCallback {
  (err: Error, body: any, res?: request.RequestResponse): void;
}

export class RequestError extends Error {
  public code: number;
  public errors: Error[];
}

export class DefaultTransporter {
  /**
   * Default user agent.
   */
  public static readonly USER_AGENT = 'google-api-nodejs-client/' + pkg.version;

  /**
   * Configures request options before making a request.
   * @param {object} opts Options to configure.
   * @return {object} Configured options.
   */
  public configure(opts: any): any {
    // set transporter user agent
    opts.headers = opts.headers || {};
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
   * @param {Function=} opt_callback Optional callback.
   * @return {Request} Request object
   */
  public request(opts: any, opt_callback: RequestCallback) {
    opts = this.configure(opts);
    return request(
        opts.uri || opts.url, opts, this.wrapCallback_(opt_callback));
  }

  /**
   * Wraps the response callback.
   * @param {Function=} opt_callback Optional callback.
   * @return {Function} Wrapped callback function.
   * @private
   */
  private wrapCallback_(opt_callback: RequestCallback):
      request.RequestCallback {
    return (err: Error, res: request.RequestResponse, body: any) => {
      if (err || !body) {
        return opt_callback && opt_callback(err, body, res);
      }
      // Only and only application/json responses should
      // be decoded back to JSON, but there are cases API back-ends
      // responds without proper content-type.
      try {
        body = JSON.parse(body);
      } catch (err) {
        /* no op */
      }

      if (body && body.error && res.statusCode !== 200) {
        if (typeof body.error === 'string') {
          err = new RequestError(body.error);
          (err as RequestError).code = res.statusCode;
        } else if (Array.isArray(body.error.errors)) {
          err = new RequestError(
              body.error.errors.map((err2: Error) => err2.message).join('\n'));
          (err as RequestError).code = body.error.code;
          (err as RequestError).errors = body.error.errors;
        } else {
          err = new RequestError(body.error.message);
          (err as RequestError).code = body.error.code || res.statusCode;
        }
        body = null;
      } else if (res.statusCode >= 500) {
        // Consider all '500 responses' errors.
        err = new RequestError(body);
        (err as RequestError).code = res.statusCode;
        body = null;
      }

      if (opt_callback) {
        opt_callback(err, body, res);
      }
    };
  }
}
