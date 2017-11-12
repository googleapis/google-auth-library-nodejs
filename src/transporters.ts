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

// tslint:disable-next-line no-var-requires
const pkg = require('../../package.json');

export interface Transporter {
  request(opts: request.Options, callback?: BodyResponseCallback):
      request.Request;
}

export interface BodyResponseCallback {
  // The `body` object is a truly dynamic type.  It must be `any`.
  // tslint:disable-next-line no-any
  (err: Error|null, body?: any, res?: request.RequestResponse|null): void;
}

export class RequestError extends Error {
  code?: number;
  errors: Error[];
}

export interface BodyResponse {
  error?: string|{
    code?: number;
    message?: string;
    errors: Error[];
  };
}

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
  configure(opts: request.Options): request.Options {
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
   * @param {Function=} callback Optional callback.
   * @return {Request} Request object
   */
  request(opts: request.Options, callback?: BodyResponseCallback) {
    opts = this.configure(opts);
    const uri = (opts as request.OptionsWithUri).uri as string ||
        (opts as request.OptionsWithUrl).url as string;
    return request(uri, opts, this.wrapCallback_(callback));
  }

  /**
   * Wraps the response callback.
   * @param {Function=} callback Optional callback.
   * @return {Function} Wrapped callback function.
   * @private
   */
  private wrapCallback_(callback?: BodyResponseCallback):
      request.RequestCallback {
    return (err: RequestError, res: request.RequestResponse,
            // the body is either a string or a JSON object
            // tslint:disable-next-line no-any
            body: string|any) => {
      if (err || !body) {
        return callback && callback(err, body, res);
      }
      // Only and only application/json responses should
      // be decoded back to JSON, but there are cases API back-ends
      // responds without proper content-type.
      try {
        body = JSON.parse(body as string);
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
      } else if (res.statusCode && res.statusCode >= 400) {
        // Consider all 4xx and 5xx responses errors.
        err = new RequestError(body);
        (err as RequestError).code = res.statusCode;
        body = null;
      }

      if (callback) {
        callback(err, body, res);
      }
    };
  }
}
