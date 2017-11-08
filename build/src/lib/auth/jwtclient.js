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
var gToken = require('gtoken');
var jwtaccess_1 = require("./jwtaccess");
var oauth2client_1 = require("./oauth2client");
var isString = require('lodash.isstring');
var noop = Function.prototype;
var JWT = /** @class */ (function (_super) {
    __extends(JWT, _super);
    /**
     * JWT service account credentials.
     *
     * Retrieve access token using gtoken.
     *
     * @param {string=} email service account email address.
     * @param {string=} keyFile path to private key file.
     * @param {string=} key value of key
     * @param {(string|array)=} scopes list of requested scopes or a single scope.
     * @param {string=} subject impersonated account's email address.
     * @constructor
     */
    function JWT(email, keyFile, key, scopes, subject) {
        var _this = _super.call(this) || this;
        _this.email = email;
        _this.keyFile = keyFile;
        _this.key = key;
        _this.scopes = scopes;
        _this.subject = subject;
        _this.gToken = gToken;
        _this.credentials = { refresh_token: 'jwt-placeholder', expiry_date: 1 };
        return _this;
    }
    /**
     * Creates a copy of the credential with the specified scopes.
     * @param {(string|array)=} scopes List of requested scopes or a single scope.
     * @return {object} The cloned instance.
     */
    JWT.prototype.createScoped = function (scopes) {
        return new JWT(this.email, this.keyFile, this.key, scopes, this.subject);
    };
    /**
     * Obtains the metadata to be sent with the request.
     *
     * @param {string} opt_uri the URI being authorized.
     * @param {function} metadataCb
     */
    JWT.prototype.getRequestMetadata = function (opt_uri, metadataCb) {
        if (this.createScopedRequired() && opt_uri) {
            // no scopes have been set, but a uri has been provided.  Use JWTAccess
            // credentials.
            var alt = new jwtaccess_1.JWTAccess(this.email, this.key);
            return alt.getRequestMetadata(opt_uri, metadataCb);
        }
        else {
            return _super.prototype.getRequestMetadata.call(this, opt_uri, metadataCb);
        }
    };
    /**
     * Indicates whether the credential requires scopes to be created by calling
     * createdScoped before use.
     * @return {boolean} false if createScoped does not need to be called.
     */
    JWT.prototype.createScopedRequired = function () {
        // If scopes is null, always return true.
        if (this.scopes) {
            // For arrays, check the array length.
            if (this.scopes instanceof Array) {
                return this.scopes.length === 0;
            }
            // For others, convert to a string and check the length.
            return String(this.scopes).length === 0;
        }
        return true;
    };
    /**
     * Get the initial access token using gToken.
     * @param {function=} callback Optional callback.
     */
    JWT.prototype.authorize = function (callback) {
        var _this = this;
        var done = callback || noop;
        this.refreshToken(null, function (err, result) {
            if (!err) {
                _this.credentials = result;
                _this.credentials.refresh_token = 'jwt-placeholder';
                _this.key = _this.gtoken.key;
                _this.email = _this.gtoken.iss;
            }
            done(err, result);
        });
    };
    /**
     * Refreshes the access token.
     * @param {object=} ignored_
     * @param {function=} callback Optional callback.
     * @private
     */
    JWT.prototype.refreshToken = function (ignored_, callback) {
        var done = callback || noop;
        return this._createGToken(function (err, gToken) {
            if (err) {
                return done(err);
            }
            else {
                return gToken.getToken(function (err2, token) {
                    return done(err2, {
                        access_token: token,
                        token_type: 'Bearer',
                        expiry_date: gToken.expires_at
                    });
                });
            }
        });
    };
    /**
     * Create a JWT credentials instance using the given input options.
     * @param {object=} json The input object.
     * @param {function=} callback Optional callback.
     */
    JWT.prototype.fromJSON = function (json, callback) {
        var done = callback || noop;
        if (!json) {
            done(new Error('Must pass in a JSON object containing the service account auth settings.'));
            return;
        }
        if (!json.client_email) {
            done(new Error('The incoming JSON object does not contain a client_email field'));
            return;
        }
        if (!json.private_key) {
            done(new Error('The incoming JSON object does not contain a private_key field'));
            return;
        }
        // Extract the relevant information from the json key file.
        this.email = json.client_email;
        this.key = json.private_key;
        this.projectId = json.project_id;
        done();
    };
    /**
     * Create a JWT credentials instance using the given input stream.
     * @param {object=} stream The input stream.
     * @param {function=} callback Optional callback.
     */
    JWT.prototype.fromStream = function (stream, callback) {
        var _this = this;
        var done = callback || noop;
        if (!stream) {
            setImmediate(function () {
                done(new Error('Must pass in a stream containing the service account auth settings.'));
            });
            return;
        }
        var s = '';
        stream.setEncoding('utf8');
        stream.on('data', function (chunk) {
            s += chunk;
        });
        stream.on('end', function () {
            try {
                var data = JSON.parse(s);
                _this.fromJSON(data, callback);
            }
            catch (err) {
                done(err);
            }
        });
    };
    /**
     * Creates a JWT credentials instance using an API Key for authentication.
     * @param {string} apiKey - the API Key in string form.
     * @param {function=} callback - Optional callback to be invoked after
     *  initialization.
     */
    JWT.prototype.fromAPIKey = function (apiKey, callback) {
        var done = callback || noop;
        if (!isString(apiKey)) {
            setImmediate(function () {
                done(new Error('Must provide an API Key string.'));
            });
            return;
        }
        this.apiKey = apiKey;
        done(null);
    };
    /**
     * Creates the gToken instance if it has not been created already.
     * @param {function=} callback Callback.
     * @private
     */
    JWT.prototype._createGToken = function (callback) {
        if (this.gtoken) {
            return callback(null, this.gtoken);
        }
        else {
            this.gtoken = this.gToken({
                iss: this.email,
                sub: this.subject,
                scope: this.scopes,
                keyFile: this.keyFile,
                key: this.key
            });
            return callback(null, this.gtoken);
        }
    };
    return JWT;
}(oauth2client_1.OAuth2Client));
exports.JWT = JWT;
