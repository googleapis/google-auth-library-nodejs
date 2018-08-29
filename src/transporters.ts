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
import {validate} from './options';

// tslint:disable-next-line variable-name
const HttpsProxyAgent = require('https-proxy-agent');

// tslint:disable-next-line no-var-requires
const pkg = require('../../package.json');
const PRODUCT_NAME = 'google-api-nodejs-client';

export interface Transporter {
  request<T>(opts: AxiosRequestConfig): AxiosPromise<T>;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      void;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      AxiosPromise|void;
}

export interface BodyResponseCallback<T> {
  // The `body` object is a truly dynamic type.  It must be `any`.
  (err: Error|null, res?: AxiosResponse<T>|null): void;
}

export interface RequestError extends AxiosError {
  errors: Error[];
}

/**
 * Axios will use XHR if it is available. In the case of Electron,
 * since XHR is there it will try to use that. This leads to OPTIONS
 * preflight requests which googleapis DOES NOT like. This line of
 * code pins the adapter to ensure it uses node.
 * https://github.com/google/google-api-nodejs-client/issues/1083
 */
axios.defaults.adapter = require('axios/lib/adapters/http');

export class DefaultTransporter {
  /**
   * Default user agent.
   */
  static readonly USER_AGENT = `${PRODUCT_NAME}/${pkg.version}`;

  /**
   * Configures request options before making a request.
   * @param opts AxiosRequestConfig options.
   * @return Configured options.
   */
  configure(opts: AxiosRequestConfig = {}): AxiosRequestConfig {
    // set transporter user agent
    opts.headers = opts.headers || {};
    const uaValue: string = opts.headers['User-Agent'];
    if (!uaValue) {
      opts.headers['User-Agent'] = DefaultTransporter.USER_AGENT;
    } else if (!uaValue.includes(`${PRODUCT_NAME}/`)) {
      opts.headers['User-Agent'] =
          `${uaValue} ${DefaultTransporter.USER_AGENT}`;
    }
    return opts;
  }

  /**
   * Makes a request using Axios with given options.
   * @param opts AxiosRequestConfig options.
   * @param callback optional callback that contains AxiosResponse object.
   * @return AxiosPromise, assuming no callback is passed.
   */
  request<T>(opts: AxiosRequestConfig): AxiosPromise<T>;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      void;
  request<T>(opts: AxiosRequestConfig, callback?: BodyResponseCallback<T>):
      AxiosPromise|void {
    // ensure the user isn't passing in request-style options
    opts = this.configure(opts);
    try {
      validate(opts);
    } catch (e) {
      if (callback) {
        return callback(e);
      } else {
        throw e;
      }
    }

    // If the user configured an `HTTPS_PROXY` environment variable, create
    // a custom agent to proxy the request.
    const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
    if (proxy) {
      opts.httpsAgent = new HttpsProxyAgent(proxy);
      opts.proxy = false;
    }

    if (callback) {
      axios(opts).then(
          r => {
            callback(null, r);
          },
          e => {
            callback(this.processError(e));
          });
    } else {
      return axios(opts).catch(e => {
        throw this.processError(e);
      });
    }
  }

  /**
   * Changes the error to include details from the body.
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
