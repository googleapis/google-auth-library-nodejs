"use strict";
/**
 * Copyright 2014 Google Inc. All Rights Reserved.
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
exports.__esModule = true;
var child_process_1 = require("child_process");
var fs = require("fs");
var os = require("os");
var path = require("path");
var util = require("util");
var transporters_1 = require("../transporters");
var computeclient_1 = require("./computeclient");
var iam_1 = require("./iam");
var jwtaccess_1 = require("./jwtaccess");
var jwtclient_1 = require("./jwtclient");
var oauth2client_1 = require("./oauth2client");
var refreshclient_1 = require("./refreshclient");
var GoogleAuth = /** @class */ (function () {
    function GoogleAuth() {
        /**
         * Caches a value indicating whether the auth layer is running on Google
         * Compute Engine.
         * @private
         */
        this._isGCE = undefined;
        this.cachedCredential = null;
        this.JWTClient = jwtclient_1.JWT;
        this.ComputeClient = computeclient_1.Compute;
        /**
         * Convenience field mapping in the IAM credential type.
         */
        this.IAMAuth = iam_1.IAMAuth;
        /**
         * Convenience field mapping in the Compute credential type.
         */
        this.Compute = computeclient_1.Compute;
        /**
         * Convenience field mapping in the JWT credential type.
         */
        this.JWT = jwtclient_1.JWT;
        /**
         * Convenience field mapping in the JWT Access credential type.
         */
        this.JWTAccess = jwtaccess_1.JWTAccess;
        /**
         * Convenience field mapping in the OAuth2 credential type.
         */
        this.OAuth2 = oauth2client_1.OAuth2Client;
        /**
         * Convenience field mapping to the UserRefreshClient credential type.
         */
        this.UserRefreshClient = refreshclient_1.UserRefreshClient;
    }
    Object.defineProperty(GoogleAuth.prototype, "isGCE", {
        // Note:  this properly is only public to satisify unit tests.
        // https://github.com/Microsoft/TypeScript/issues/5228
        get: function () {
            return this._isGCE;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(GoogleAuth.prototype, "cachedProjectId", {
        // Note:  this properly is only public to satisify unit tests.
        // https://github.com/Microsoft/TypeScript/issues/5228
        set: function (projectId) {
            this._cachedProjectId = projectId;
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Obtains the default project ID for the application..
     * @param {function=} callback Optional callback.
     */
    GoogleAuth.prototype.getDefaultProjectId = function (callback) {
        // In implicit case, supports three environments. In order of precedence,
        // the implicit environments are:
        //
        // * GCLOUD_PROJECT or GOOGLE_CLOUD_PROJECT environment variable
        // * GOOGLE_APPLICATION_CREDENTIALS JSON file
        // * Get default service project from
        //  ``$ gcloud beta auth application-default login``
        // * Google App Engine application ID (Not implemented yet)
        // * Google Compute Engine project ID (from metadata server) (Not
        // implemented yet)
        var _this = this;
        if (this._cachedProjectId) {
            setImmediate(function () {
                _this.callback(callback, null, _this._cachedProjectId);
            });
        }
        else {
            var my_callback_1 = function (err, projectId) {
                if (!err && projectId) {
                    _this._cachedProjectId = projectId;
                }
                setImmediate(function () {
                    _this.callback(callback, err, projectId);
                });
            };
            // environment variable
            if (this._getProductionProjectId(my_callback_1)) {
                return;
            }
            // json file
            this._getFileProjectId(function (err, projectId) {
                if (err || projectId) {
                    my_callback_1(err, projectId);
                    return;
                }
                // Google Cloud SDK default project id
                _this._getDefaultServiceProjectId(function (err2, projectId2) {
                    if (err2 || projectId2) {
                        my_callback_1(err2, projectId2);
                        return;
                    }
                    // Get project ID from Compute Engine metadata server
                    _this._getGCEProjectId(my_callback_1);
                });
            });
        }
    };
    /**
     * Run the Google Cloud SDK command that prints the default project ID
     * @param {function} _callback Callback.
     * @api private
     */
    GoogleAuth.prototype._getSDKDefaultProjectId = function (_callback) {
        child_process_1.exec('gcloud -q config list core/project --format=json', _callback);
    };
    /**
     * Obtains the default service-level credentials for the application..
     * @param {function=} callback Optional callback.
     */
    GoogleAuth.prototype.getApplicationDefault = function (callback) {
        var _this = this;
        // If we've already got a cached credential, just return it.
        if (this.cachedCredential) {
            setImmediate(function () {
                _this.callback(callback, null, _this.cachedCredential, _this._cachedProjectId);
            });
        }
        else {
            // Inject our own callback routine, which will cache the credential once
            // it's been created. It also allows us to ensure that the ultimate
            // callback is always async.
            var my_callback_2 = function (err, result) {
                if (!err && result) {
                    _this.cachedCredential = result;
                    _this.getDefaultProjectId(function (err2, projectId) {
                        setImmediate(function () {
                            // Ignore default project error
                            _this.callback(callback, null, result, projectId);
                        });
                    });
                }
                else {
                    setImmediate(function () {
                        _this.callback(callback, err, result);
                    });
                }
            };
            // Check for the existence of a local environment variable pointing to the
            // location of the credential file. This is typically used in local
            // developer scenarios.
            if (this._tryGetApplicationCredentialsFromEnvironmentVariable(my_callback_2)) {
                return;
            }
            // Look in the well-known credential file location.
            if (this._tryGetApplicationCredentialsFromWellKnownFile(my_callback_2)) {
                return;
            }
            // Determine if we're running on GCE.
            this._checkIsGCE(function (err, gce) {
                if (gce) {
                    // For GCE, just return a default ComputeClient. It will take care of
                    // the rest.
                    my_callback_2(null, new _this.ComputeClient());
                }
                else if (err) {
                    my_callback_2(new Error('Unexpected error while acquiring application default ' +
                        'credentials: ' + err.message));
                }
                else {
                    // We failed to find the default credentials. Bail out with an error.
                    my_callback_2(new Error('Could not load the default credentials. Browse to ' +
                        'https://developers.google.com/accounts/docs/application-default-credentials for ' +
                        'more information.'));
                }
            });
        }
    };
    /**
     * Determines whether the auth layer is running on Google Compute Engine.
     * @param {function=} callback The callback.
     * @api private
     */
    GoogleAuth.prototype._checkIsGCE = function (callback) {
        var _this = this;
        if (this._isGCE !== undefined) {
            setImmediate(function () {
                callback(null, _this._isGCE);
            });
        }
        else {
            if (!this.transporter) {
                this.transporter = new transporters_1.DefaultTransporter();
            }
            this.transporter.request({ method: 'GET', uri: 'http://metadata.google.internal', json: true }, function (err, body, res) {
                if (err) {
                    if (err.code !== 'ENOTFOUND') {
                        // Unexpected error occurred. TODO(ofrobots): retry if this was
                        // a transient error.
                        return callback(err);
                    }
                    _this._isGCE = false;
                    return callback(null, _this._isGCE);
                }
                _this._isGCE = res && res.headers &&
                    res.headers['metadata-flavor'] === 'Google';
                callback(null, _this._isGCE);
            });
        }
    };
    /**
     * Attempts to load default credentials from the environment variable path..
     * @param {function=} callback Optional callback.
     * @return {boolean} Returns true if the callback has been executed; false otherwise.
     * @api private
     */
    GoogleAuth.prototype._tryGetApplicationCredentialsFromEnvironmentVariable = function (callback) {
        var _this = this;
        var credentialsPath = this._getEnv('GOOGLE_APPLICATION_CREDENTIALS');
        if (!credentialsPath || credentialsPath.length === 0) {
            return false;
        }
        this._getApplicationCredentialsFromFilePath(credentialsPath, function (err, result) {
            var wrappedError = null;
            if (err) {
                wrappedError = _this.createError('Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS ' +
                    'environment variable.', err);
            }
            _this.callback(callback, wrappedError, result);
        });
        return true;
    };
    /**
     * Attempts to load default credentials from a well-known file location
     * @param {function=} callback Optional callback.
     * @return {boolean} Returns true if the callback has been executed; false otherwise.
     * @api private
     */
    GoogleAuth.prototype._tryGetApplicationCredentialsFromWellKnownFile = function (callback) {
        // First, figure out the location of the file, depending upon the OS type.
        var location = null;
        if (this._isWindows()) {
            // Windows
            location = this._getEnv('APPDATA');
        }
        else {
            // Linux or Mac
            var home = this._getEnv('HOME');
            if (home) {
                location = this._pathJoin(home, '.config');
            }
        }
        // If we found the root path, expand it.
        if (location) {
            location = this._pathJoin(location, 'gcloud');
            location =
                this._pathJoin(location, 'application_default_credentials.json');
            location = this._mockWellKnownFilePath(location);
            // Check whether the file exists.
            if (!this._fileExists(location)) {
                location = null;
            }
        }
        // The file does not exist.
        if (!location) {
            return false;
        }
        // The file seems to exist. Try to use it.
        this._getApplicationCredentialsFromFilePath(location, callback);
        return true;
    };
    /**
     * Attempts to load default credentials from a file at the given path..
     * @param {string=} filePath The path to the file to read.
     * @param {function=} callback Optional callback.
     * @api private
     */
    GoogleAuth.prototype._getApplicationCredentialsFromFilePath = function (filePath, callback) {
        var error = null;
        // Make sure the path looks like a string.
        if (!filePath || filePath.length === 0) {
            error = new Error('The file path is invalid.');
        }
        // Make sure there is a file at the path. lstatSync will throw if there is
        // nothing there.
        if (!error) {
            try {
                // Resolve path to actual file in case of symlink. Expect a thrown error
                // if not resolvable.
                filePath = fs.realpathSync(filePath);
                if (!fs.lstatSync(filePath).isFile()) {
                    throw new Error();
                }
            }
            catch (err) {
                error = this.createError(util.format('The file at %s does not exist, or it is not a file.', filePath), err);
            }
        }
        // Now open a read stream on the file, and parse it.
        if (!error) {
            try {
                var stream_1 = this._createReadStream(filePath);
                this.fromStream(stream_1, callback);
            }
            catch (err) {
                error = this.createError(util.format('Unable to read the file at %s.', filePath), err);
            }
        }
        if (error) {
            this.callback(callback, error);
        }
    };
    /**
     * Create a credentials instance using the given input options.
     * @param {object=} json The input object.
     * @param {function=} callback Optional callback.
     */
    GoogleAuth.prototype.fromJSON = function (json, callback) {
        var _this = this;
        var client = null;
        if (!json) {
            this.callback(callback, new Error('Must pass in a JSON object containing the Google auth settings.'));
            return;
        }
        if (json.type === 'authorized_user') {
            client = new refreshclient_1.UserRefreshClient();
        }
        else {
            client = new jwtclient_1.JWT();
        }
        client.fromJSON(json, function (err) {
            if (err) {
                _this.callback(callback, err);
            }
            else {
                _this.callback(callback, null, client);
            }
        });
    };
    /**
     * Create a credentials instance using the given input stream.
     * @param {object=} stream The input stream.
     * @param {function=} callback Optional callback.
     */
    GoogleAuth.prototype.fromStream = function (stream, callback) {
        var _this = this;
        if (!stream) {
            setImmediate(function () {
                _this.callback(callback, new Error('Must pass in a stream containing the Google auth settings.'));
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
                _this.callback(callback, err);
            }
        });
    };
    /**
     * Create a credentials instance using the given API key string.
     * @param {string} - The API key string
     * @param {function=} - Optional callback function
     */
    GoogleAuth.prototype.fromAPIKey = function (apiKey, callback) {
        var _this = this;
        var client = new this.JWTClient();
        client.fromAPIKey(apiKey, function (err) {
            if (err) {
                _this.callback(callback, err);
            }
            else {
                _this.callback(callback, null, client);
            }
        });
    };
    /**
     * Determines whether the current operating system is Windows.
     * @api private
     */
    GoogleAuth.prototype._isWindows = function () {
        var sys = this._osPlatform();
        if (sys && sys.length >= 3) {
            if (sys.substring(0, 3).toLowerCase() === 'win') {
                return true;
            }
        }
        return false;
    };
    /**
     * Creates a file stream. Allows mocking.
     * @api private
     */
    GoogleAuth.prototype._createReadStream = function (filePath) {
        return fs.createReadStream(filePath);
    };
    /**
     * Gets the value of the environment variable with the given name. Allows
     * mocking.
     * @api private
     */
    GoogleAuth.prototype._getEnv = function (name) {
        return process.env[name];
    };
    /**
     * Gets the current operating system platform. Allows mocking.
     * @api private
     */
    GoogleAuth.prototype._osPlatform = function () {
        return os.platform();
    };
    /**
     * Determines whether a file exists. Allows mocking.
     * @api private
     */
    GoogleAuth.prototype._fileExists = function (filePath) {
        return fs.existsSync(filePath);
    };
    /**
     * Joins two parts of a path. Allows mocking.
     * @api private
     */
    GoogleAuth.prototype._pathJoin = function (item1, item2) {
        return path.join(item1, item2);
    };
    /**
     * Allows mocking of the path to a well-known file.
     * @api private
     */
    GoogleAuth.prototype._mockWellKnownFilePath = function (filePath) {
        return filePath;
    };
    // Executes the given callback if it is not null.
    GoogleAuth.prototype.callback = function (c, err) {
        var args = [];
        for (var _i = 2; _i < arguments.length; _i++) {
            args[_i - 2] = arguments[_i];
        }
        if (c) {
            return c.apply(null, Array.prototype.slice.call(arguments, 1));
        }
    };
    // Creates an Error containing the given message, and includes the message
    // from the optional err passed in.
    GoogleAuth.prototype.createError = function (message, err) {
        var s = message || '';
        if (err) {
            var errorMessage = String(err);
            if (errorMessage && errorMessage.length > 0) {
                if (s.length > 0) {
                    s += ' ';
                }
                s += errorMessage;
            }
        }
        return Error(s);
    };
    /**
     * Loads the default project of the Google Cloud SDK.
     * @param {function} _callback Callback.
     * @api private
     */
    GoogleAuth.prototype._getDefaultServiceProjectId = function (_callback) {
        var _this = this;
        this._getSDKDefaultProjectId(function (err, stdout) {
            var projectId = null;
            if (!err && stdout) {
                try {
                    projectId = JSON.parse(stdout).core.project;
                }
                catch (err) {
                    projectId = null;
                }
            }
            // Ignore any errors
            _this.callback(_callback, null, projectId);
        });
    };
    /**
     * Loads the project id from environment variables.
     * @param {function} _callback Callback.
     * @api private
     */
    GoogleAuth.prototype._getProductionProjectId = function (_callback) {
        var _this = this;
        var projectId = this._getEnv('GCLOUD_PROJECT') || this._getEnv('GOOGLE_CLOUD_PROJECT');
        if (projectId) {
            setImmediate(function () {
                _this.callback(_callback, null, projectId);
            });
        }
        return projectId;
    };
    /**
     * Loads the project id from the GOOGLE_APPLICATION_CREDENTIALS json file.
     * @param {function} _callback Callback.
     * @api private
     */
    GoogleAuth.prototype._getFileProjectId = function (_callback) {
        var _this = this;
        if (this.cachedCredential) {
            // Try to read the project ID from the cached credentials file
            setImmediate(function () {
                _this.callback(_callback, null, _this.cachedCredential.projectId);
            });
            return;
        }
        // Try to load a credentials file and read its project ID
        var pathExists = this._tryGetApplicationCredentialsFromEnvironmentVariable(function (err, result) {
            if (!err && result) {
                _this.callback(_callback, null, result.projectId);
                return;
            }
            _this.callback(_callback, err);
        });
        if (!pathExists) {
            this.callback(_callback, null);
        }
    };
    /**
     * Gets the Compute Engine project ID if it can be inferred.
     * Uses 169.254.169.254 for the metadata server to avoid request
     * latency from DNS lookup.
     * See https://cloud.google.com/compute/docs/metadata#metadataserver
     * for information about this IP address. (This IP is also used for
     * Amazon EC2 instances, so the metadata flavor is crucial.)
     * See https://github.com/google/oauth2client/issues/93 for context about
     * DNS latency.
     *
     * @param {function} _callback Callback.
     * @api private
     */
    GoogleAuth.prototype._getGCEProjectId = function (_callback) {
        var _this = this;
        if (!this.transporter) {
            this.transporter = new transporters_1.DefaultTransporter();
        }
        this.transporter.request({
            method: 'GET',
            uri: 'http://169.254.169.254/computeMetadata/v1/project/project-id',
            headers: { 'Metadata-Flavor': 'Google' }
        }, function (err, body, res) {
            if (err || !res || res.statusCode !== 200 || !body) {
                _this.callback(_callback);
                return;
            }
            // Ignore any errors
            _this.callback(_callback, null, body);
        });
    };
    /**
     * Export DefaultTransporter as a static property of the class.
     */
    GoogleAuth.DefaultTransporter = transporters_1.DefaultTransporter;
    return GoogleAuth;
}());
exports.GoogleAuth = GoogleAuth;
