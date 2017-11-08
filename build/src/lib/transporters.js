"use strict";
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
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
var request = require("request");
// tslint:disable-next-line
var pkg = require('../package.json');
var RequestError = /** @class */ (function (_super) {
    __extends(RequestError, _super);
    function RequestError() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return RequestError;
}(Error));
exports.RequestError = RequestError;
var DefaultTransporter = /** @class */ (function () {
    function DefaultTransporter() {
    }
    /**
     * Configures request options before making a request.
     * @param {object} opts Options to configure.
     * @return {object} Configured options.
     */
    DefaultTransporter.prototype.configure = function (opts) {
        // set transporter user agent
        opts.headers = opts.headers || {};
        if (!opts.headers['User-Agent']) {
            opts.headers['User-Agent'] = DefaultTransporter.USER_AGENT;
        }
        else if (opts.headers['User-Agent'].indexOf(DefaultTransporter.USER_AGENT) ===
            -1) {
            opts.headers['User-Agent'] =
                opts.headers['User-Agent'] + ' ' + DefaultTransporter.USER_AGENT;
        }
        return opts;
    };
    /**
     * Makes a request with given options and invokes callback.
     * @param {object} opts Options.
     * @param {Function=} callback Optional callback.
     * @return {Request} Request object
     */
    DefaultTransporter.prototype.request = function (opts, callback) {
        opts = this.configure(opts);
        return request(opts.uri || opts.url, opts, this.wrapCallback_(callback));
    };
    /**
     * Wraps the response callback.
     * @param {Function=} callback Optional callback.
     * @return {Function} Wrapped callback function.
     * @private
     */
    DefaultTransporter.prototype.wrapCallback_ = function (callback) {
        return function (err, res, body) {
            if (err || !body) {
                return callback && callback(err, body, res);
            }
            // Only and only application/json responses should
            // be decoded back to JSON, but there are cases API back-ends
            // responds without proper content-type.
            try {
                body = JSON.parse(body);
            }
            catch (err) {
                /* no op */
            }
            if (body && body.error && res.statusCode !== 200) {
                if (typeof body.error === 'string') {
                    err = new RequestError(body.error);
                    err.code = res.statusCode;
                }
                else if (Array.isArray(body.error.errors)) {
                    err = new RequestError(body.error.errors.map(function (err2) { return err2.message; }).join('\n'));
                    err.code = body.error.code;
                    err.errors = body.error.errors;
                }
                else {
                    err = new RequestError(body.error.message);
                    err.code = body.error.code || res.statusCode;
                }
                body = null;
            }
            else if (res.statusCode >= 400) {
                // Consider all 4xx and 5xx responses errors.
                err = new RequestError(body);
                err.code = res.statusCode;
                body = null;
            }
            if (callback) {
                callback(err, body, res);
            }
        };
    };
    /**
     * Default user agent.
     */
    DefaultTransporter.USER_AGENT = 'google-api-nodejs-client/' + pkg.version;
    return DefaultTransporter;
}());
exports.DefaultTransporter = DefaultTransporter;
