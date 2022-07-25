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

import * as sinon from 'sinon';
import * as child_process from 'child_process';
import {ReadStream} from 'fs';
import * as fs from 'fs';
import {
  ExecutableResponse,
  ExecutableResponseJson,
  InvalidExpirationTimeFieldError,
  InvalidSuccessFieldError,
} from '../src/auth/executable-response';
import {beforeEach} from 'mocha';
import * as events from 'events';
import * as stream from 'stream';
import {
  PluggableAuthHandler,
  PluggableAuthHandlerOptions,
} from '../src/auth/pluggable-auth-handler';
import * as assert from 'assert';
import {ExecutableError} from '../src/auth/pluggable-auth-client';

const SAML_SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:saml2';

describe('PluggableAuthHandler', () => {
  const defaultHandlerOptions = {
    command: './command/path/file.exe -opt',
    outputFile: 'output',
    timeoutMillis: 1000,
  } as PluggableAuthHandlerOptions;

  describe('Constructor', () => {
    it('should not throw error with valid options', () => {
      const client = new PluggableAuthHandler(defaultHandlerOptions);

      assert(client instanceof PluggableAuthHandler);
    });

    it('should throw when options is missing command', () => {
      const expectedError = new Error('No command provided.');
      const invalidOptions = {
        outputFile: 'output.txt',
        timeoutMillis: 1000,
      };

      assert.throws(() => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return new PluggableAuthHandler(invalidOptions);
      }, expectedError);
    });

    it('should throw when options is missing timeoutMillis', () => {
      const expectedError = new Error('No timeoutMillis provided.');
      const invalidOptions = {
        command: './command -opt',
        outputFile: 'output.txt',
      };

      assert.throws(() => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return new PluggableAuthHandler(invalidOptions);
      }, expectedError);
    });

    it('should throw when command cannot be parsed', async () => {
      const expectedError = new Error(
        'Provided command: " " could not be parsed.'
      );
      const invalidHandlerOptions = {
        command: ' ',
        timeoutMillis: 10000,
      } as PluggableAuthHandlerOptions;

      assert.throws(() => {
        return new PluggableAuthHandler(invalidHandlerOptions);
      }, expectedError);
    });
  });

  describe('RetrieveResponseFromExecutable', () => {
    const sandbox = sinon.createSandbox();
    let clock: sinon.SinonFakeTimers;
    const referenceTime = Date.now();
    let spawnEvent: child_process.ChildProcess;
    let spawnStub: sinon.SinonStub<
      [
        command: string,
        args: readonly string[],
        options: child_process.SpawnOptions
      ],
      child_process.ChildProcess
    >;
    let defaultResponseJson: ExecutableResponseJson;
    const expectedEnvMap = new Map();
    expectedEnvMap.set(
      'GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE',
      SAML_SUBJECT_TOKEN_TYPE
    );
    expectedEnvMap.set('GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE', '0');
    const expectedOpts = {
      env: {
        ...process.env,
        ...Object.fromEntries(expectedEnvMap),
      },
    };

    beforeEach(() => {
      // Stub environment variables and set Allow Executables environment variable to 1
      const envVars = Object.assign({}, process.env, {
        GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES: '1',
      });
      sandbox.stub(process, 'env').value(envVars);
      clock = sandbox.useFakeTimers({now: referenceTime});

      defaultResponseJson = {
        success: true,
        version: 1,
        token_type: SAML_SUBJECT_TOKEN_TYPE,
        saml_response: 'response',
        expiration_time: referenceTime / 1000 + 10,
      } as ExecutableResponseJson;

      // Stub child_process.spawn to return an event emitter.
      spawnEvent = new events.EventEmitter() as child_process.ChildProcess;
      spawnEvent.stdout = new events.EventEmitter() as stream.Readable;
      spawnEvent.stderr = new events.EventEmitter() as stream.Readable;
      spawnStub = sandbox.stub(child_process, 'spawn').returns(spawnEvent);
    });

    afterEach(() => {
      sandbox.restore();
      if (clock) {
        clock.restore();
      }
    });

    it('should return error from child process up the stack', async () => {
      const expectedError = new Error('example error');
      spawnStub.throws(new Error('example error'));
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      await assert.rejects(
        handler.retrieveResponseFromExecutable(new Map<string, string>()),
        expectedError
      );
    });

    it('should return executable response when successful', async () => {
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      const response = handler.retrieveResponseFromExecutable(
        new Map<string, string>()
      );
      spawnEvent.stdout!.emit('data', JSON.stringify(defaultResponseJson));
      spawnEvent.emit('close', 0);

      assert.deepEqual(
        await response,
        new ExecutableResponse(defaultResponseJson)
      );
    });

    it('should call executable with correct command and env variables', async () => {
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const components = defaultHandlerOptions.command.split(' ');
      const expectedCommand = components[0];
      const expectedArgs = components.slice(1);

      const response = handler.retrieveResponseFromExecutable(expectedEnvMap);
      spawnEvent.stdout!.emit('data', JSON.stringify(defaultResponseJson));
      spawnEvent.emit('close', 0);
      await response;

      sandbox.assert.calledOnceWithMatch(
        spawnStub,
        expectedCommand,
        expectedArgs,
        expectedOpts
      );
    });

    it('should call executable with correct command with spaces', async () => {
      const handlerOptions = {
        command: '"./command with/spaces.exe" -opt arg',
        outputFile: 'output',
        timeoutMillis: 1000,
      } as PluggableAuthHandlerOptions;
      const handler = new PluggableAuthHandler(handlerOptions);
      const expectedCommand = './command with/spaces.exe';
      const expectedArgs = ['-opt', 'arg'];

      const response = handler.retrieveResponseFromExecutable(expectedEnvMap);
      spawnEvent.stdout!.emit('data', JSON.stringify(defaultResponseJson));
      spawnEvent.emit('close', 0);
      await response;

      sandbox.assert.calledOnceWithMatch(
        spawnStub,
        expectedCommand,
        expectedArgs,
        expectedOpts
      );
    });

    it('should call executable with correct arguments with spaces', async () => {
      const handlerOptions = {
        command: './command/with/path.exe -opt "arg with spaces"',
        outputFile: 'output',
        timeoutMillis: 1000,
      } as PluggableAuthHandlerOptions;
      const handler = new PluggableAuthHandler(handlerOptions);
      const expectedCommand = './command/with/path.exe';
      const expectedArgs = ['-opt', 'arg with spaces'];

      const response = handler.retrieveResponseFromExecutable(expectedEnvMap);
      spawnEvent.stdout!.emit('data', JSON.stringify(defaultResponseJson));
      spawnEvent.emit('close', 0);
      await response;

      sandbox.assert.calledOnceWithMatch(
        spawnStub,
        expectedCommand,
        expectedArgs,
        expectedOpts
      );
    });

    it('should throw ExecutableError when executable fails', async () => {
      const expectedError = new ExecutableError('test error', '1');
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      const response = handler.retrieveResponseFromExecutable(
        new Map<string, string>()
      );
      spawnEvent.stderr!.emit('error', 'test error');
      spawnEvent.emit('close', 1);

      await assert.rejects(response, expectedError);
    });

    it('should throw error when executable times out', async () => {
      const expectedError = new Error(
        'The executable failed to finish within the timeout specified.'
      );
      spawnEvent.kill = () => {
        return true;
      };
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      const response = handler.retrieveResponseFromExecutable(
        new Map<string, string>()
      );
      clock.tick(10001);

      await assert.rejects(response, expectedError);
    });

    it('should throw error when non-json text is returned', async () => {
      const expectedError = new Error(
        'Executable returned invalid response: Invalid response'
      );
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      const response = handler.retrieveResponseFromExecutable(
        new Map<string, string>()
      );
      spawnEvent.stdout!.emit('data', 'Invalid response');
      spawnEvent.emit('close', 0);

      await assert.rejects(response, expectedError);
    });

    it('should throw ExecutableResponseError', async () => {
      const expectedError = new InvalidSuccessFieldError(
        "Executable response must contain a 'success' field."
      );
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const invalidResponse = {
        version: 1,
        token_type: SAML_SUBJECT_TOKEN_TYPE,
        saml_response: 'response',
        expiration_time: referenceTime / 1000 + 10,
      };

      const response = handler.retrieveResponseFromExecutable(
        new Map<string, string>()
      );
      spawnEvent.stdout!.emit('data', JSON.stringify(invalidResponse));
      spawnEvent.emit('close', 0);

      await assert.rejects(response, expectedError);
    });
  });

  describe('retrieveCachedResponse', () => {
    const sandbox = sinon.createSandbox();
    let clock: sinon.SinonFakeTimers;
    const referenceTime = Date.now();
    let fileEvent: ReadStream;
    let statSyncStub: sinon.SinonStub<
      [path: fs.PathLike, options?: fs.StatSyncOptions | undefined],
      fs.Stats | fs.BigIntStats | undefined
    >;
    let defaultResponseJson: ExecutableResponseJson;

    beforeEach(() => {
      clock = sandbox.useFakeTimers({now: referenceTime});

      defaultResponseJson = {
        success: true,
        version: 1,
        token_type: SAML_SUBJECT_TOKEN_TYPE,
        saml_response: 'response',
        expiration_time: referenceTime / 1000 + 10,
      } as ExecutableResponseJson;

      // Stub fs methods, so we don't have to read a real file.
      sandbox.stub(fs, 'realpathSync').returnsArg(0);
      const fakeStat = {isFile: () => true} as fs.Stats;
      statSyncStub = sandbox.stub(fs, 'lstatSync').returns(fakeStat);
      fileEvent = new events.EventEmitter() as ReadStream;
      fileEvent.setEncoding = () => {
        return fileEvent;
      };
      sandbox.stub(fs, 'createReadStream').returns(fileEvent);
    });

    afterEach(() => {
      sandbox.restore();
      if (clock) {
        clock.restore();
      }
    });

    it('should return cached file response when successful', async () => {
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(defaultResponseJson));
      fileEvent.emit('end', 0);

      assert.deepEqual(
        await response,
        new ExecutableResponse(defaultResponseJson)
      );
    });

    it('should reject if error returned from output file stream', async () => {
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const expectedError = new Error('error');
      const response = handler.retrieveCachedResponse();
      fileEvent.emit('error', 'error');

      await assert.rejects(response, expectedError);
    });

    it('should return undefined if file response is expired', async () => {
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      defaultResponseJson.expiration_time = referenceTime / 1000 - 10;
      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(defaultResponseJson));
      fileEvent.emit('end', 0);

      assert.equal(await response, undefined);
    });

    it('should return undefined if outputFile is undefined', async () => {
      const invalidOptions = {
        command: './command.sh',
        timeoutMillis: 1000,
      };
      const handler = new PluggableAuthHandler(invalidOptions);
      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(defaultResponseJson));
      fileEvent.emit('end', 0);

      assert.equal(await response, undefined);
    });

    it('should return undefined if output file does not exist', async () => {
      const fakeStat = {isFile: () => false} as fs.Stats;
      statSyncStub.returns(fakeStat);
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(defaultResponseJson));
      fileEvent.emit('end', 0);

      assert.equal(await response, undefined);
    });

    it('should throw error when non-json text is returned', async () => {
      const expectedError = new Error(
        'Output file contained invalid response: Invalid response'
      );
      const handler = new PluggableAuthHandler(defaultHandlerOptions);

      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', 'Invalid response');
      fileEvent.emit('end', 0);

      await assert.rejects(response, expectedError);
    });

    it('should throw ExecutableResponseError', async () => {
      const expectedError = new InvalidSuccessFieldError(
        "Executable response must contain a 'success' field."
      );
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const invalidResponse = {
        version: 1,
        token_type: SAML_SUBJECT_TOKEN_TYPE,
        saml_response: 'response',
        expiration_time: referenceTime / 1000 + 10,
      };

      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(invalidResponse));
      fileEvent.emit('end', 0);

      await assert.rejects(response, expectedError);
    });

    it('should throw InvalidExpirationTimeError', async () => {
      const expectedError = new InvalidExpirationTimeFieldError(
        'Output file response must contain an expiration_time when success=true.'
      );
      const handler = new PluggableAuthHandler(defaultHandlerOptions);
      const invalidResponse = {
        success: true,
        version: 1,
        token_type: SAML_SUBJECT_TOKEN_TYPE,
        saml_response: 'response',
      };

      const response = handler.retrieveCachedResponse();
      fileEvent.emit('data', JSON.stringify(invalidResponse));
      fileEvent.emit('end', 0);

      await assert.rejects(response, expectedError);
    });
  });
});
