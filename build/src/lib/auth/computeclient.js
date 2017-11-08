"use strict";
/**
 * Copyright 2013 Google Inc. All Rights Reserved.
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
var oauth2client_1 = require("./oauth2client");
var Compute = /** @class */ (function (_super) {
    __extends(Compute, _super);
    /**
     * Google Compute Engine service account credentials.
     *
     * Retrieve access token from the metadata server.
     * See: https://developers.google.com/compute/docs/authentication
     */
    function Compute() {
        var _this = _super.call(this) || this;
        // Start with an expired refresh token, which will automatically be
        // refreshed before the first API call is made.
        _this.credentials = { expiry_date: 1, refresh_token: 'compute-placeholder' };
        return _this;
    }
    /**
     * Indicates whether the credential requires scopes to be created by calling
     * createdScoped before use.
     * @return {object} The cloned instance.
     */
    Compute.prototype.createScopedRequired = function () {
        // On compute engine, scopes are specified at the compute instance's
        // creation time, and cannot be changed. For this reason, always return
        // false.
        return false;
    };
    /**
     * Refreshes the access token.
     * @param {object=} ignored_
     * @param {function=} callback Optional callback.
     */
    Compute.prototype.refreshToken = function (ignored, callback) {
        var uri = this._opts.tokenUrl || Compute._GOOGLE_OAUTH2_TOKEN_URL;
        // request for new token
        return this.transporter.request({ method: 'GET', uri: uri, json: true }, function (err, body, response) {
            var token = body;
            if (!err && token && token.expires_in) {
                token.expiry_date =
                    ((new Date()).getTime() + (token.expires_in * 1000));
                delete token.expires_in;
            }
            if (callback) {
                callback(err, token, response);
            }
        });
    };
    /**
     * Inserts a helpful error message guiding the user toward fixing common auth
     * issues.
     * @param {object} err Error result.
     * @param {object} result The result.
     * @param {object} response The HTTP response.
     * @param {Function} callback The callback.
     */
    Compute.prototype.postRequest = function (err, result, response, callback) {
        if (response && response.statusCode) {
            var helpfulMessage = null;
            if (response.statusCode === 403) {
                helpfulMessage =
                    'A Forbidden error was returned while attempting to retrieve an access ' +
                        'token for the Compute Engine built-in service account. This may be because the Compute ' +
                        'Engine instance does not have the correct permission scopes specified.';
            }
            else if (response.statusCode === 404) {
                helpfulMessage =
                    'A Not Found error was returned while attempting to retrieve an access' +
                        'token for the Compute Engine built-in service account. This may be because the Compute ' +
                        'Engine instance does not have any permission scopes specified.';
            }
            if (helpfulMessage) {
                if (err && err.message) {
                    helpfulMessage += ' ' + err.message;
                }
                if (err) {
                    err.message = helpfulMessage;
                }
                else {
                    err = new Error(helpfulMessage);
                    err.code = response.statusCode;
                }
            }
        }
        callback(err, result, response);
    };
    /**
     * Google Compute Engine metadata server token endpoint.
     */
    Compute._GOOGLE_OAUTH2_TOKEN_URL = 'http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token';
    return Compute;
}(oauth2client_1.OAuth2Client));
exports.Compute = Compute;
