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

import {exec} from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as stream from 'stream';
import * as util from 'util';

import {DefaultTransporter, Transporter} from '../transporters';

import {BodyResponseCallback} from './../transporters';
import {Compute} from './computeclient';
import {IAMAuth} from './iam';
import {JWTAccess} from './jwtaccess';
import {JWT} from './jwtclient';
import {OAuth2Client} from './oauth2client';
import {UserRefreshClient} from './refreshclient';

export interface ProjectIdCallback { (err: Error, projectId: string): void }

export class GoogleAuth {
  public transporter: Transporter;

  /**
   * Caches a value indicating whether the auth layer is running on Google
   * Compute Engine.
   * @private
   */
  private _isGCE: boolean = undefined;

  // Note:  this properly is only public to satisify unit tests.
  // https://github.com/Microsoft/TypeScript/issues/5228
  get isGCE() {
    return this._isGCE;
  }

  private _cachedProjectId: string;

  // Note:  this properly is only public to satisify unit tests.
  // https://github.com/Microsoft/TypeScript/issues/5228
  set cachedProjectId(projectId: string) {
    this._cachedProjectId = projectId;
  }

  public cachedCredential: any = null;

  protected JWTClient = JWT;
  protected ComputeClient = Compute;

  /**
   * Convenience field mapping in the IAM credential type.
   */
  public IAMAuth = IAMAuth;

  /**
   * Convenience field mapping in the Compute credential type.
   */
  public Compute = Compute;

  /**
   * Convenience field mapping in the JWT credential type.
   */
  public JWT = JWT;

  /**
   * Convenience field mapping in the JWT Access credential type.
   */
  public JWTAccess = JWTAccess;

  /**
   * Convenience field mapping in the OAuth2 credential type.
   */
  public OAuth2 = OAuth2Client;

  /**
   * Convenience field mapping to the UserRefreshClient credential type.
   */
  public UserRefreshClient = UserRefreshClient;

  /**
   * Export DefaultTransporter as a static property of the class.
   */
  public static DefaultTransporter = DefaultTransporter;

  /**
   * Obtains the default project ID for the application..
   * @param {function=} callback Optional callback.
   */
  public getDefaultProjectId(callback: ProjectIdCallback) {
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

    if (this._cachedProjectId) {
      setImmediate(() => {
        this.callback(callback, null, this._cachedProjectId);
      });
    } else {
      const my_callback = (err: Error, projectId: string) => {
        if (!err && projectId) {
          this._cachedProjectId = projectId;
        }
        setImmediate(() => {
          this.callback(callback, err, projectId);
        });
      };

      // environment variable
      if (this._getProductionProjectId(my_callback)) {
        return;
      }

      // json file
      this._getFileProjectId((err: Error, projectId: string) => {
        if (err || projectId) {
          my_callback(err, projectId);
          return;
        }

        // Google Cloud SDK default project id
        this._getDefaultServiceProjectId((err2: Error, projectId2: string) => {
          if (err2 || projectId2) {
            my_callback(err2, projectId2);
            return;
          }

          // Get project ID from Compute Engine metadata server
          this._getGCEProjectId(my_callback);
        });
      });
    }
  }

  /**
   * Run the Google Cloud SDK command that prints the default project ID
   * @param {function} _callback Callback.
   * @api private
   */
  public _getSDKDefaultProjectId(
      _callback: (error: Error, stdout: string, stderr: string) => void) {
    exec('gcloud -q config list core/project --format=json', _callback);
  }

  /**
   * Obtains the default service-level credentials for the application..
   * @param {function=} callback Optional callback.
   */
  public getApplicationDefault(
      callback?: (err: Error, credential: any, projectId: string) => void) {
    // If we've already got a cached credential, just return it.
    if (this.cachedCredential) {
      setImmediate(() => {
        this.callback(
            callback, null, this.cachedCredential, this._cachedProjectId);
      });
    } else {
      // Inject our own callback routine, which will cache the credential once
      // it's been created. It also allows us to ensure that the ultimate
      // callback is always async.
      const my_callback = (err: Error, result?: any) => {
        if (!err && result) {
          this.cachedCredential = result;
          this.getDefaultProjectId((err2, projectId) => {
            setImmediate(() => {
              // Ignore default project error
              this.callback(callback, null, result, projectId);
            });
          });
        } else {
          setImmediate(() => {
            this.callback(callback, err, result);
          });
        }
      };

      // Check for the existence of a local environment variable pointing to the
      // location of the credential file. This is typically used in local
      // developer scenarios.
      if (this._tryGetApplicationCredentialsFromEnvironmentVariable(
              my_callback)) {
        return;
      }

      // Look in the well-known credential file location.
      if (this._tryGetApplicationCredentialsFromWellKnownFile(my_callback)) {
        return;
      }

      // Determine if we're running on GCE.
      this._checkIsGCE((gce) => {
        if (gce) {
          // For GCE, just return a default ComputeClient. It will take care of
          // the rest.
          my_callback(null, new this.ComputeClient());
        } else {
          // We failed to find the default credentials. Bail out with an error.
          my_callback(new Error(
              'Could not load the default credentials. Browse to ' +
              'https://developers.google.com/accounts/docs/application-default-credentials for ' +
              'more information.'));
        }
      });
    }
  }

  /**
   * Determines whether the auth layer is running on Google Compute Engine.
   * @param {function=} callback The callback.
   * @api private
   */
  public _checkIsGCE(callback: (isGCE: boolean) => void) {
    if (this._isGCE !== undefined) {
      callback(this._isGCE);
    } else {
      if (!this.transporter) {
        this.transporter = new DefaultTransporter();
      }
      this.transporter.request(
          {method: 'GET', uri: 'http://metadata.google.internal', json: true},
          (err, body, res) => {
            if (!err && res && res.headers) {
              this._isGCE = res.headers['metadata-flavor'] === 'Google';
            }
            callback(this._isGCE);
          });
    }
  }

  /**
   * Attempts to load default credentials from the environment variable path..
   * @param {function=} callback Optional callback.
   * @return {boolean} Returns true if the callback has been executed; false otherwise.
   * @api private
   */
  public _tryGetApplicationCredentialsFromEnvironmentVariable(
      callback?: (err: Error, result: any) => void) {
    const credentialsPath = this._getEnv('GOOGLE_APPLICATION_CREDENTIALS');
    if (!credentialsPath || credentialsPath.length === 0) {
      return false;
    }
    this._getApplicationCredentialsFromFilePath(credentialsPath, (err, result) => {
      let wrappedError = null;
      if (err) {
        wrappedError = this.createError(
            'Unable to read the credential file specified by the GOOGLE_APPLICATION_CREDENTIALS ' +
                'environment variable.',
            err);
      }
      this.callback(callback, wrappedError, result);
    });
    return true;
  }

  /**
   * Attempts to load default credentials from a well-known file location
   * @param {function=} callback Optional callback.
   * @return {boolean} Returns true if the callback has been executed; false otherwise.
   * @api private
   */
  public _tryGetApplicationCredentialsFromWellKnownFile(
      callback?: (err: Error, result?: any) => void) {
    // First, figure out the location of the file, depending upon the OS type.
    let location = null;
    if (this._isWindows()) {
      // Windows
      location = this._getEnv('APPDATA');
    } else {
      // Linux or Mac
      const home = this._getEnv('HOME');
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
  }

  /**
   * Attempts to load default credentials from a file at the given path..
   * @param {string=} filePath The path to the file to read.
   * @param {function=} callback Optional callback.
   * @api private
   */
  public _getApplicationCredentialsFromFilePath(
      filePath: string, callback: (err: Error, result?: any) => void) {
    let error = null;
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
      } catch (err) {
        error = this.createError(
            util.format(
                'The file at %s does not exist, or it is not a file.',
                filePath),
            err);
      }
    }
    // Now open a read stream on the file, and parse it.
    if (!error) {
      try {
        const stream = this._createReadStream(filePath);
        this.fromStream(stream, callback);
      } catch (err) {
        error = this.createError(
            util.format('Unable to read the file at %s.', filePath), err);
      }
    }
    if (error) {
      this.callback(callback, error);
    }
  }

  /**
   * Create a credentials instance using the given input options.
   * @param {object=} json The input object.
   * @param {function=} callback Optional callback.
   */
  public fromJSON(json: any, callback?: (err: Error, client?: any) => void) {
    let client: UserRefreshClient|JWT = null;
    if (!json) {
      this.callback(
          callback,
          new Error(
              'Must pass in a JSON object containing the Google auth settings.'));
      return;
    }
    if (json.type === 'authorized_user') {
      client = new UserRefreshClient();
    } else {
      client = new JWT();
    }

    client.fromJSON(json, (err: Error) => {
      if (err) {
        this.callback(callback, err);
      } else {
        this.callback(callback, null, client);
      }
    });
  }

  /**
   * Create a credentials instance using the given input stream.
   * @param {object=} stream The input stream.
   * @param {function=} callback Optional callback.
   */
  public fromStream(
      stream: stream.Readable, callback?: (err: Error, result?: any) => void) {
    if (!stream) {
      setImmediate(() => {
        this.callback(
            callback,
            new Error(
                'Must pass in a stream containing the Google auth settings.'));
      });
      return;
    }
    let s = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      s += chunk;
    });
    stream.on('end', () => {
      try {
        const data = JSON.parse(s);
        this.fromJSON(data, callback);
      } catch (err) {
        this.callback(callback, err);
      }
    });
  }

  /**
   * Create a credentials instance using the given API key string.
   * @param {string} - The API key string
   * @param {function=} - Optional callback function
   */
  public fromAPIKey(
      apiKey: string, callback?: (err: Error, client?: JWT) => void) {
    const client = new this.JWTClient();
    client.fromAPIKey(apiKey, (err) => {
      if (err) {
        this.callback(callback, err);
      } else {
        this.callback(callback, null, client);
      }
    });
  }

  /**
   * Determines whether the current operating system is Windows.
   * @api private
   */
  private _isWindows() {
    const sys = this._osPlatform();
    if (sys && sys.length >= 3) {
      if (sys.substring(0, 3).toLowerCase() === 'win') {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates a file stream. Allows mocking.
   * @api private
   */
  public _createReadStream(filePath: string) {
    return fs.createReadStream(filePath);
  }

  /**
   * Gets the value of the environment variable with the given name. Allows
   * mocking.
   * @api private
   */
  private _getEnv(name: string) {
    return process.env[name];
  }

  /**
   * Gets the current operating system platform. Allows mocking.
   * @api private
   */
  public _osPlatform() {
    return os.platform();
  }

  /**
   * Determines whether a file exists. Allows mocking.
   * @api private
   */
  public _fileExists(filePath: string) {
    return fs.existsSync(filePath);
  }

  /**
   * Joins two parts of a path. Allows mocking.
   * @api private
   */
  public _pathJoin(item1: string, item2: string) {
    return path.join(item1, item2);
  }

  /**
   * Allows mocking of the path to a well-known file.
   * @api private
   */
  private _mockWellKnownFilePath(filePath: string) {
    return filePath;
  }

  // Executes the given callback if it is not null.
  private callback(c: Function, err?: Error, ...args: any[]) {
    if (c) {
      return c.apply(null, Array.prototype.slice.call(arguments, 1));
    }
  }

  // Creates an Error containing the given message, and includes the message
  // from the optional err passed in.
  private createError(message: string, err: Error) {
    let s = message || '';
    if (err) {
      const errorMessage = String(err);
      if (errorMessage && errorMessage.length > 0) {
        if (s.length > 0) {
          s += ' ';
        }
        s += errorMessage;
      }
    }
    return Error(s);
  }

  /**
   * Loads the default project of the Google Cloud SDK.
   * @param {function} _callback Callback.
   * @api private
   */
  private _getDefaultServiceProjectId(_callback: ProjectIdCallback) {
    this._getSDKDefaultProjectId((err, stdout) => {
      let projectId = null;
      if (!err && stdout) {
        try {
          projectId = JSON.parse(stdout).core.project;
        } catch (err) {
          projectId = null;
        }
      }
      // Ignore any errors
      this.callback(_callback, null, projectId);
    });
  }

  /**
   * Loads the project id from environment variables.
   * @param {function} _callback Callback.
   * @api private
   */
  private _getProductionProjectId(_callback: ProjectIdCallback) {
    const projectId =
        this._getEnv('GCLOUD_PROJECT') || this._getEnv('GOOGLE_CLOUD_PROJECT');
    if (projectId) {
      setImmediate(() => {
        this.callback(_callback, null, projectId);
      });
    }
    return projectId;
  }

  /**
   * Loads the project id from the GOOGLE_APPLICATION_CREDENTIALS json file.
   * @param {function} _callback Callback.
   * @api private
   */
  private _getFileProjectId(_callback: ProjectIdCallback) {
    if (this.cachedCredential) {
      // Try to read the project ID from the cached credentials file
      setImmediate(() => {
        this.callback(_callback, null, this.cachedCredential.projectId);
      });
      return;
    }

    // Try to load a credentials file and read its project ID
    const pathExists =
        this._tryGetApplicationCredentialsFromEnvironmentVariable(
            (err, result) => {
              if (!err && result) {
                this.callback(_callback, null, result.projectId);
                return;
              }
              this.callback(_callback, err);
            });

    if (!pathExists) {
      this.callback(_callback, null);
    }
  }

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
  private _getGCEProjectId(_callback: BodyResponseCallback) {
    if (!this.transporter) {
      this.transporter = new DefaultTransporter();
    }
    this.transporter.request(
        {
          method: 'GET',
          uri: 'http://169.254.169.254/computeMetadata/v1/project/project-id',
          headers: {'Metadata-Flavor': 'Google'}
        },
        (err, body, res) => {
          if (err || !res || res.statusCode !== 200 || !body) {
            this.callback(_callback);
            return;
          }
          // Ignore any errors
          this.callback(_callback, null, body);
        });
  }
}
