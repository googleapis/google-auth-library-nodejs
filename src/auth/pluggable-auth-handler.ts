// Copyright 2022 Google LLC
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

import {ExecutableError} from './pluggable-auth-client';
import {
  ExecutableResponse,
  ExecutableResponseJson,
} from './executable-response';
import * as childProcess from 'child_process';
import * as fs from 'fs';

/**
 * Defines the options used for the PluggableAuthHandler class.
 */
export interface PluggableAuthHandlerOptions {
  /**
   * The command used to retrieve the third party token.
   */
  command: string;
  /**
   * The timeout in milliseconds for running executable,
   * set to default if none provided.
   */
  timeoutMillis: number;
  /**
   * The path to file to check for cached executable response.
   */
  outputFile?: string;
}

/**
 * A handler used to retrieve 3rd party token responses from user defined
 * executables and cached file output for the PluggableAuthClient class.
 */
export class PluggableAuthHandler {
  private readonly command: string;
  private readonly timeoutMillis: number;
  private readonly outputFile?: string;

  /**
   * Instantiates a PluggableAuthHandler instance using the provided
   * PluggableAuthHandlerOptions object.
   */
  constructor(options: PluggableAuthHandlerOptions) {
    this.command = options.command;
    if (!this.command) {
      throw new Error('No valid command provided.');
    }
    this.timeoutMillis = options.timeoutMillis;
    if (!this.timeoutMillis) {
      throw new Error('No valid timeoutMillis provided.');
    }
    this.outputFile = options.outputFile;
  }

  /**
   * Calls user provided executable to get a 3rd party subject token and
   * returns the response.
   * @param envMap a Map of additional Environment Variables required for
   *   the executable.
   * @return A promise that resolves with the executable response.
   */
  retrieveResponseFromExecutable(
    envMap: Map<string, string>
  ): Promise<ExecutableResponse> {
    // Split command into components on ' '.
    const components = this.command.split(' ');
    return new Promise((resolve, reject) => {
      // Spawn process to run executable using added environment variables
      const child = childProcess.spawn(components[0], components.slice(1), {
        env: {...process.env, ...Object.fromEntries(envMap)},
      });
      let output = '';
      let error = '';
      // Append stdout to output as executable runs.
      child.stdout.on('data', (data: string) => {
        output += data;
      });
      // Append stderr as executable runs
      child.stderr.on('error', (err: string) => {
        error += err;
      });

      // Set up a timeout to end the child process and throw an error.
      const timeout = setTimeout(() => {
        child.kill();
        reject(new Error('Executable failed due to timeout.'));
      }, this.timeoutMillis);

      child.on('close', (code: number) => {
        // Cancel timeout if executable closes before timeout is reached.
        clearTimeout(timeout);
        if (code === 0) {
          // If executable completed successfully, try to return parsed response
          const responseJson = JSON.parse(output) as ExecutableResponseJson;
          resolve(new ExecutableResponse(responseJson));
        } else {
          reject(new ExecutableError(error, code.toString()));
        }
      });
    });
  }

  /**
   * Checks user provided output file for response from previous run of
   * executable and return the response if it exists and is valid.
   */
  retrieveCachedResponse(): Promise<ExecutableResponse | undefined> {
    return new Promise((resolve, reject) => {
      if (!this.outputFile || this.outputFile.length === 0) {
        resolve(undefined);
      }

      const filePath = fs.realpathSync(this.outputFile as string);

      if (!fs.lstatSync(filePath).isFile()) {
        resolve(undefined);
      }

      const readStream = fs.createReadStream(filePath);
      let s = '';
      readStream
        .setEncoding('utf8')
        .on('error', (err: string) => {
          reject(new Error(err));
        })
        .on('data', (chunk: string) => (s += chunk))
        .on('end', () => {
          const responseJson = JSON.parse(s) as ExecutableResponseJson;
          const response = new ExecutableResponse(responseJson);
          if (response.isExpired()) {
            resolve(undefined);
          }
          resolve(new ExecutableResponse(responseJson));
        });
    });
  }
}
