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

import {PassThroughClient} from '../src';
import {snakeToCamel} from '../src/util';
import {Gaxios} from 'gaxios';

describe('AuthClient', () => {
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
      let authClient = new PassThroughClient({[key]: value});
      assert.equal(authClient[camelCased], value);

      // assert camel cased input
      authClient = new PassThroughClient({[camelCased]: value});
      assert.equal(authClient[camelCased], value);
    }
  });

  it('should allow disabling of the default interceptor', () => {
    const gaxios = new Gaxios();
    const originalInterceptorCount = gaxios.interceptors.request.size;

    const authClient = new PassThroughClient({
      gaxios,
      useAuthRequestParameters: false,
    });

    assert.equal(authClient.transporter, gaxios);
    assert.equal(
      authClient.transporter.interceptors.request.size,
      originalInterceptorCount
    );
  });

  it('should add the default interceptor exactly once between instances', () => {
    const gaxios = new Gaxios();
    const originalInterceptorCount = gaxios.interceptors.request.size;
    const expectedInterceptorCount = originalInterceptorCount + 1;

    new PassThroughClient({gaxios});
    new PassThroughClient({gaxios});

    assert.equal(gaxios.interceptors.request.size, expectedInterceptorCount);
  });
});
