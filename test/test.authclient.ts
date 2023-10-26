// Copyright 2023 Google LLC
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

import {strict as assert} from 'assert';

import {GaxiosOptions, GaxiosPromise, GaxiosResponse} from 'gaxios';
import {AuthClient} from '../src';
import {Headers} from '../src/auth/oauth2client';
import {snakeToCamel} from '../src/util';

describe('AuthClient', () => {
  class TestAuthClient extends AuthClient {
    request<T>(opts: GaxiosOptions): GaxiosPromise<T> {
      throw new Error('Method not implemented.');
    }

    getRequestHeaders(url?: string | undefined): Promise<Headers> {
      throw new Error('Method not implemented.');
    }

    getAccessToken(): Promise<{
      token?: string | null | undefined;
      res?: GaxiosResponse<any> | null | undefined;
    }> {
      throw new Error('Method not implemented.');
    }
  }

  it('should accept and normalize snake case options to camel case', () => {
    const expected = {
      project_id: 'my-projectId',
      quota_project_id: 'my-quota-project-id',
      credentials: {},
      universe_domain: 'my-universe-domain',
    };

    for (const [key, value] of Object.entries(expected)) {
      const camelCased = snakeToCamel(key) as keyof typeof authClient;

      // assert snake cased input
      let authClient = new TestAuthClient({[key]: value});
      assert.equal(authClient[camelCased], value);

      // assert camel cased input
      authClient = new TestAuthClient({[camelCased]: value});
      assert.equal(authClient[camelCased], value);
    }
  });
});
