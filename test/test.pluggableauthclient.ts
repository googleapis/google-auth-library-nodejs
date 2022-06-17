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

import * as assert from 'assert';
import {PluggableAuthClient} from '../src/auth/pluggableauthclient';
import {BaseExternalAccountClient} from '../src';
import {getAudience, getTokenUrl} from './externalclienthelper';
import {beforeEach} from 'mocha';

describe('PluggableAuthClient', () => {
  const audience = getAudience();
  const pluggableAuthCredentialSource = {
    command: './command',
    output_file: 'output.txt',
    timeout_millis: 10000,
  };
  const pluggableAuthOptions = {
    type: 'external_account',
    audience,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: getTokenUrl(),
    credential_source: pluggableAuthCredentialSource,
  };

  it('should be a subclass of ExternalAccountClient', () => {
    assert(PluggableAuthClient.prototype instanceof BaseExternalAccountClient);
  });

  describe('Constructor', () => {
    it('should throw when credential_source is missing command', () => {
      const expectedError = new Error(
        'No valid Pluggable Auth "credential_source" provided.'
      );
      const invalidCredentialSource = Object.assign(
        {},
        pluggableAuthCredentialSource
      );
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (invalidCredentialSource as any)['command'];
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: invalidCredentialSource,
      };

      assert.throws(() => {
        return new PluggableAuthClient(invalidOptions);
      }, expectedError);
    });

    it('should throw when time_millis is below minimum allowed value', () => {
      const expectedError = new Error(
        'Timeout must be between 5000 and 120000 milliseconds.'
      );
      const invalidCredentialSource = Object.assign(
        {},
        pluggableAuthCredentialSource
      );
      invalidCredentialSource.timeout_millis = 0;
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: invalidCredentialSource,
      };

      assert.throws(() => {
        return new PluggableAuthClient(invalidOptions);
      }, expectedError);
    });

    it('should throw when time_millis is above maximum allowed value', () => {
      const expectedError = new Error(
        'Timeout must be between 5000 and 120000 milliseconds.'
      );
      const invalidCredentialSource = Object.assign(
        {},
        pluggableAuthCredentialSource
      );
      invalidCredentialSource.timeout_millis = 9000000000;
      const invalidOptions = {
        type: 'external_account',
        audience,
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: getTokenUrl(),
        credential_source: invalidCredentialSource,
      };

      assert.throws(() => {
        return new PluggableAuthClient(invalidOptions);
      }, expectedError);
    });
  });

  describe('RetrieveSubjectToken', () => {
    beforeEach(() => {
      // Set Allow Executables environment variables to 1
      process.env.GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = '1';
    });

    afterEach(() => {
      delete process.env.GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES;
    });

    it('should throw when allow executables environment variables is not 1', async () => {
      process.env.GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES = '0';
      const expectedError = new Error(
        'Pluggable Auth executables need to be explicitly allowed to run by setting the GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES environment Variable to 1.'
      );

      const client = new PluggableAuthClient(pluggableAuthOptions);

      await assert.rejects(client.retrieveSubjectToken(), expectedError);
    });
  });
});
