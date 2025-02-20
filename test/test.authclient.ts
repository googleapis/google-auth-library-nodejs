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

import {Gaxios, GaxiosOptions, GaxiosOptionsPrepared} from 'gaxios';
import * as nock from 'nock';

import {AuthClient, PassThroughClient} from '../src';
import {snakeToCamel} from '../src/util';
import {PRODUCT_NAME, USER_AGENT} from '../src/shared.cjs';

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

  describe('fetch', () => {
    const url = 'https://google.com';

    it('should accept a `string`', async () => {
      const scope = nock(url).get('/').reply(200, {});

      const authClient = new PassThroughClient();
      const res = await authClient.fetch(url);

      scope.done();
      assert(typeof url === 'string');
      assert.deepStrictEqual(res.data, {});
    });

    it('should accept a `URL`', async () => {
      const scope = nock(url).get('/').reply(200, {});

      const authClient = new PassThroughClient();
      const res = await authClient.fetch(new URL(url));

      scope.done();
      assert.deepStrictEqual(res.data, {});
    });

    it('should accept an input with initialization', async () => {
      const scope = nock(url).post('/', 'abc').reply(200, {});

      const authClient = new PassThroughClient();
      const res = await authClient.fetch(url, {
        body: Buffer.from('abc'),
        method: 'POST',
      });

      scope.done();
      assert.deepStrictEqual(res.data, {});
    });

    it('should accept `GaxiosOptions`', async () => {
      const scope = nock(url).post('/', 'abc').reply(200, {});

      const authClient = new PassThroughClient();
      const options: GaxiosOptions = {
        body: Buffer.from('abc'),
        method: 'POST',
      };
      const res = await authClient.fetch(url, options);

      scope.done();
      assert.deepStrictEqual(res.data, {});
    });
  });

  describe('shared auth interceptor', () => {
    it('should use the default interceptor', () => {
      const gaxios = new Gaxios();

      new PassThroughClient({transporter: gaxios});

      assert(
        gaxios.interceptors.request.has(AuthClient.DEFAULT_REQUEST_INTERCEPTOR)
      );
    });

    it('should allow disabling of the default interceptor', () => {
      const gaxios = new Gaxios();
      const originalInterceptorCount = gaxios.interceptors.request.size;

      const authClient = new PassThroughClient({
        transporter: gaxios,
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

      new PassThroughClient({transporter: gaxios});
      new PassThroughClient({transporter: gaxios});

      assert.equal(gaxios.interceptors.request.size, expectedInterceptorCount);
    });

    describe('User-Agent', () => {
      it('should set the header if it does not exist', async () => {
        const options: GaxiosOptionsPrepared = {
          headers: new Headers(),
          url: new URL('https://google.com'),
        };

        await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);

        assert.equal(options.headers?.get('User-Agent'), USER_AGENT);
      });

      it('should append to the header if it does exist and does not have the product name', async () => {
        const base = 'ABC XYZ';
        const expected = `${base} ${USER_AGENT}`;
        const options: GaxiosOptionsPrepared = {
          headers: new Headers({
            'User-Agent': base,
          }),
          url: new URL('https://google.com'),
        };

        await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);

        assert.equal(options.headers.get('User-Agent'), expected);
      });

      it('should not append to the header if it does exist and does have the product name', async () => {
        const expected = `ABC ${PRODUCT_NAME}/XYZ`;
        const options: GaxiosOptionsPrepared = {
          headers: new Headers({
            'User-Agent': expected,
          }),
          url: new URL('https://google.com'),
        };

        await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);

        assert.equal(options.headers.get('User-Agent'), expected);
      });
    });

    describe('x-goog-api-client', () => {
      it('should set the header if it does not exist', async () => {
        const options: GaxiosOptionsPrepared = {
          headers: new Headers(),
          url: new URL('https://google.com'),
        };

        await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);

        assert.equal(
          options.headers.get('x-goog-api-client'),
          `gl-node/${process.version.replace(/^v/, '')}`
        );
      });

      it('should not overwrite an existing header', async () => {
        const expected = 'abc';
        const options: GaxiosOptionsPrepared = {
          headers: new Headers({
            'x-goog-api-client': expected,
          }),
          url: new URL('https://google.com'),
        };

        await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);

        assert.equal(options.headers.get('x-goog-api-client'), expected);
      });
    });
  });
});
