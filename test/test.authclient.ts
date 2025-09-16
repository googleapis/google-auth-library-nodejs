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

import * as nock from 'nock';
import {
  Gaxios,
  GaxiosError,
  GaxiosOptions,
  GaxiosOptionsPrepared,
  GaxiosResponse,
} from 'gaxios';

import {AuthClient, Compute, PassThroughClient} from '../src';
import {snakeToCamel} from '../src/util';
import {PRODUCT_NAME, USER_AGENT} from '../src/shared.cjs';
import * as logging from 'google-logging-utils';
import {BASE_PATH, HOST_ADDRESS, HEADERS} from 'gcp-metadata';
import sinon = require('sinon');
import {
  TrustBoundaryData,
  SERVICE_ACCOUNT_LOOKUP_ENDPOINT,
  NoOpEncodedLocations,
} from '../src/auth/trustboundary';

// Fakes for the logger, to capture logs that would've happened.
interface TestLog {
  namespace: string;
  fields: logging.LogFields;
  args: unknown[];
}

class TestLogSink extends logging.DebugLogBackendBase {
  logs: TestLog[] = [];

  makeLogger(namespace: string): logging.AdhocDebugLogCallable {
    return (fields: logging.LogFields, ...args: unknown[]) => {
      this.logs.push({namespace, fields, args});
    };
  }

  setFilters(): void {}

  reset() {
    this.filters = [];
    this.logs = [];
  }
}

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

  describe('shared auth interceptors', () => {
    it('should use the default interceptors', () => {
      const gaxios = new Gaxios();

      new PassThroughClient({transporter: gaxios});

      assert(
        gaxios.interceptors.request.has(AuthClient.DEFAULT_REQUEST_INTERCEPTOR),
      );
      assert(
        gaxios.interceptors.response.has(
          AuthClient.DEFAULT_RESPONSE_INTERCEPTOR,
        ),
      );
    });

    it('should allow disabling of the default interceptor', () => {
      const gaxios = new Gaxios();
      const originalRequestInterceptorCount = gaxios.interceptors.request.size;
      const originalResponseInterceptorCount =
        gaxios.interceptors.response.size;

      const authClient = new PassThroughClient({
        transporter: gaxios,
        useAuthRequestParameters: false,
      });

      assert.equal(authClient.transporter, gaxios);
      assert.equal(
        authClient.transporter.interceptors.request.size,
        originalRequestInterceptorCount,
      );
      assert.equal(
        authClient.transporter.interceptors.response.size,
        originalResponseInterceptorCount,
      );
    });

    it('should add the default interceptor exactly once between instances', () => {
      const gaxios = new Gaxios();
      const originalRequestInterceptorCount = gaxios.interceptors.request.size;
      const expectedRequestInterceptorCount =
        originalRequestInterceptorCount + 1;
      const originalResponseInterceptorCount =
        gaxios.interceptors.response.size;
      const expectedResponseInterceptorCount =
        originalResponseInterceptorCount + 1;

      new PassThroughClient({transporter: gaxios});
      new PassThroughClient({transporter: gaxios});

      assert.equal(
        gaxios.interceptors.request.size,
        expectedRequestInterceptorCount,
      );
      assert.equal(
        gaxios.interceptors.response.size,
        expectedResponseInterceptorCount,
      );
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
          `gl-node/${process.version.replace(/^v/, '')}`,
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

    describe('logging', () => {
      // Enable and capture any log lines that happen during these tests.
      let testLogSink: TestLogSink;
      let replacementLogger: logging.AdhocDebugLogFunction;
      beforeEach(() => {
        process.env[logging.env.nodeEnables] = 'auth';
        testLogSink = new TestLogSink();
        logging.setBackend(testLogSink);
        replacementLogger = logging.log('auth');
      });
      after(() => {
        delete process.env[logging.env.nodeEnables];
        logging.setBackend(null);
      });

      it('logs requests', async () => {
        const options: GaxiosOptionsPrepared = {
          headers: new Headers({
            'x-goog-api-client': 'something',
          }),
          url: new URL('https://google.com'),
        };
        AuthClient.setMethodName(options, 'testMethod');

        // This will become nicer with the 1.1.0 release of google-logging-utils.
        AuthClient.log = replacementLogger;
        const returned =
          await AuthClient.DEFAULT_REQUEST_INTERCEPTOR?.resolved?.(options);
        assert.strictEqual(returned, options);

        // Unfortunately, there is a fair amount of entropy and changeable formatting in the
        // actual logs, so this mostly validates that a few key pieces of info are in there.
        assert.deepStrictEqual(testLogSink.logs.length, 1);
        assert.deepStrictEqual(testLogSink.logs[0].namespace, 'auth');
        assert.deepStrictEqual(testLogSink.logs[0].args.length, 4);
        assert.strictEqual(
          (testLogSink.logs[0].args[0] as string).includes('request'),
          true,
        );
        assert.deepStrictEqual(testLogSink.logs[0].args[1], 'testMethod');
        assert.deepStrictEqual(
          (testLogSink.logs[0].args[3] as GaxiosOptionsPrepared).headers.get(
            'x-goog-api-client',
          ),
          'something',
        );
        assert.deepStrictEqual(
          (testLogSink.logs[0].args[3] as GaxiosOptionsPrepared).url.href,
          'https://google.com/',
        );
      });

      it('logs responses', async () => {
        const response = {
          config: {
            headers: new Headers({
              'x-goog-api-client': 'something',
            }),
            url: new URL('https://google.com'),
          } as GaxiosOptionsPrepared,
          headers: new Headers({
            'x-goog-api-client': 'something',
          }),
          url: new URL('https://google.com'),
          data: {
            test: 'test!',
          },
        } as unknown as GaxiosResponse<{test: string}>;
        AuthClient.setMethodName(response.config, 'testMethod');

        // This will become nicer with the 1.1.0 release of google-logging-utils.
        AuthClient.log = replacementLogger;
        const resolvedReturned =
          await AuthClient.DEFAULT_RESPONSE_INTERCEPTOR?.resolved?.(response);
        assert.strictEqual(resolvedReturned, response);

        // Unfortunately, there is a fair amount of entropy and changeable formatting in the
        // actual logs, so this mostly validates that a few key pieces of info are in there.
        assert.deepStrictEqual(testLogSink.logs.length, 1);
        assert.deepStrictEqual(testLogSink.logs[0].namespace, 'auth');
        assert.deepStrictEqual(testLogSink.logs[0].args.length, 4);
        assert.strictEqual(
          (testLogSink.logs[0].args[0] as string).includes('response'),
          true,
        );
        assert.deepStrictEqual(testLogSink.logs[0].args[1], 'testMethod');
        assert.deepStrictEqual(testLogSink.logs[0].args[3] as {test: string}, {
          test: 'test!',
        });

        const error = {
          config: response.config,
          response: {
            data: {
              message: 'boo!',
            },
          },
        } as unknown as GaxiosError<{test: string}>;
        testLogSink.reset();
        AuthClient.DEFAULT_RESPONSE_INTERCEPTOR?.rejected?.(error);

        // Unfortunately, there is a fair amount of entropy and changeable formatting in the
        // actual logs, so this mostly validates that a few key pieces of info are in there.
        assert.deepStrictEqual(testLogSink.logs.length, 1);
        assert.deepStrictEqual(testLogSink.logs[0].namespace, 'auth');
        assert.deepStrictEqual(testLogSink.logs[0].args.length, 4);
        assert.strictEqual(
          (testLogSink.logs[0].args[0] as string).includes('error'),
          true,
        );
        assert.deepStrictEqual(testLogSink.logs[0].args[1], 'testMethod');
        assert.deepStrictEqual(testLogSink.logs[0].args[3] as {test: string}, {
          message: 'boo!',
        });
      });
    });
  });

  describe('trust boundaries', () => {
    const url = 'http://example.com';

    function mockExample() {
      return nock(url).get('/').reply(200);
    }

    let sandbox: sinon.SinonSandbox;
    const MOCK_ACCESS_TOKEN = 'abc123';
    const MOCK_AUTH_HEADER = `Bearer ${MOCK_ACCESS_TOKEN}`;
    const SERVICE_ACCOUNT_EMAIL = 'service-account@example.com';
    const EXPECTED_TB_DATA: TrustBoundaryData = {
      locations: ['sadad', 'asdad'],
      encodedLocations: '000x9',
    };
    const NO_OP_TB_DATA: TrustBoundaryData = {
      encodedLocations: '0x0',
    };

    function setupTokenNock(email: string | 'default' = 'default'): nock.Scope {
      const tokenPath =
        email === 'default'
          ? `${BASE_PATH}/instance/service-accounts/default/token`
          : `${BASE_PATH}/instance/service-accounts/${email}/token`;
      return nock(HOST_ADDRESS)
        .get(tokenPath)
        .reply(
          200,
          {access_token: MOCK_ACCESS_TOKEN, expires_in: 10000},
          HEADERS,
        );
    }

    function setupExpiredTokenNock(
      email: string | 'default' = 'default',
    ): nock.Scope {
      const tokenPath =
        email === 'default'
          ? `${BASE_PATH}/instance/service-accounts/default/token`
          : `${BASE_PATH}/instance/service-accounts/${email}/token`;
      return nock(HOST_ADDRESS)
        .get(tokenPath)
        .reply(200, {access_token: MOCK_ACCESS_TOKEN, expires_in: -1}, HEADERS);
    }

    function setupTrustBoundaryNock(
      email: string,
      trustBoundaryData: TrustBoundaryData = EXPECTED_TB_DATA,
    ): nock.Scope {
      const lookupUrl = SERVICE_ACCOUNT_LOOKUP_ENDPOINT.replace(
        '{universe_domain}',
        'googleapis.com',
      ).replace('{service_account_email}', encodeURIComponent(email));
      return nock(new URL(lookupUrl).origin)
        .get(new URL(lookupUrl).pathname)
        .matchHeader('authorization', MOCK_AUTH_HEADER)
        .reply(200, trustBoundaryData);
    }

    beforeEach(() => {
      sandbox = sinon.createSandbox();
      process.env['GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED'] = 'true';
    });

    afterEach(() => {
      delete process.env['GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED'];
      sandbox.restore();
      nock.cleanAll();
    });

    it('should fetch and return trust boundary data successfully', async () => {
      const compute = new Compute({serviceAccountEmail: SERVICE_ACCOUNT_EMAIL});
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL),
        mockExample(),
      ];

      await compute.request({url});

      assert.deepStrictEqual(compute.trustBoundary, EXPECTED_TB_DATA);
      scopes.forEach(s => s.done());
    });

    it('should retry trust boundary lookup on failure', async () => {
      const compute = new Compute({serviceAccountEmail: SERVICE_ACCOUNT_EMAIL});
      const lookupUrl = SERVICE_ACCOUNT_LOOKUP_ENDPOINT.replace(
        '{universe_domain}',
        'googleapis.com',
      ).replace(
        '{service_account_email}',
        encodeURIComponent(SERVICE_ACCOUNT_EMAIL),
      );
      const tbScopeFail = nock(new URL(lookupUrl).origin)
        .get(new URL(lookupUrl).pathname)
        .matchHeader('authorization', MOCK_AUTH_HEADER)
        .reply(503, {error: 'server unavailable'});
      const tbScopeSuccess = nock(new URL(lookupUrl).origin)
        .get(new URL(lookupUrl).pathname)
        .matchHeader('authorization', MOCK_AUTH_HEADER)
        .reply(200, EXPECTED_TB_DATA);
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        tbScopeFail,
        tbScopeSuccess,
        mockExample(),
      ];

      await compute.request({url});

      // The request should have succeeded after the retry.
      assert.deepStrictEqual(compute.trustBoundary, EXPECTED_TB_DATA);
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should return null when default domain is not googleapis.com', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
        universe_domain: 'abc.com',
      });
      const scopes = [setupTokenNock(SERVICE_ACCOUNT_EMAIL), mockExample()];

      await compute.request({url});

      assert.deepStrictEqual(compute.trustBoundary, null);
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should throw when no valid access token is passed', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });
      const scopes = [setupExpiredTokenNock(SERVICE_ACCOUNT_EMAIL)];

      await assert.rejects(
        compute.request({url}),
        new RegExp(
          'TrustBoundary: Error calling lookup endpoint without valid access token',
        ),
      );
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should return no-op and not call lookup endpoint in case cachedTrustBoundaries is no-op', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });
      compute.trustBoundary = {encodedLocations: NoOpEncodedLocations};
      const scopes = [setupTokenNock(SERVICE_ACCOUNT_EMAIL), mockExample()];
      const tbScope = setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL);

      await compute.request({url});
      assert.deepStrictEqual(
        compute.trustBoundary.encodedLocations,
        NoOpEncodedLocations,
      );
      scopes.forEach(s => s.done());
      assert.strictEqual(tbScope.isDone(), false);
    });

    it('refreshTrustBoundary should return no-op if response from lookup is no-op', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL, NO_OP_TB_DATA),
        mockExample(),
      ];

      await compute.request({url});
      assert.deepStrictEqual(
        compute?.trustBoundary?.encodedLocations,
        NoOpEncodedLocations,
      );
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should return cached TB if call to lookup fails', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });
      compute.trustBoundary = EXPECTED_TB_DATA;

      const lookupUrl = SERVICE_ACCOUNT_LOOKUP_ENDPOINT.replace(
        '{universe_domain}',
        'googleapis.com',
      ).replace(
        '{service_account_email}',
        encodeURIComponent(SERVICE_ACCOUNT_EMAIL),
      );

      const tbErrorScope = nock(new URL(lookupUrl).origin)
        .get(new URL(lookupUrl).pathname)
        .matchHeader('authorization', MOCK_AUTH_HEADER)
        .replyWithError('Something wrong!');

      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        tbErrorScope,
        mockExample(),
      ];

      await compute.request({url});
      assert.deepStrictEqual(compute.trustBoundary, EXPECTED_TB_DATA);
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should throw if call to lookup fails and no cached-TB', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });

      const lookupUrl = SERVICE_ACCOUNT_LOOKUP_ENDPOINT.replace(
        '{universe_domain}',
        'googleapis.com',
      ).replace(
        '{service_account_email}',
        encodeURIComponent(SERVICE_ACCOUNT_EMAIL),
      );

      const tbErrorScope = nock(new URL(lookupUrl).origin)
        .get(new URL(lookupUrl).pathname)
        .matchHeader('authorization', MOCK_AUTH_HEADER)
        .replyWithError('Something wrong!');

      const scopes = [setupTokenNock(SERVICE_ACCOUNT_EMAIL), tbErrorScope];

      await assert.rejects(
        compute.request({url}),
        new RegExp('TrustBoundary: Failure while getting trust boundaries:'),
      );
      scopes.forEach(s => s.done());
    });

    it('refreshTrustBoundary should throw in case of malformed response from lookup', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
      });
      const malformedTBData: TrustBoundaryData = {
        locations: ['sadad', 'asdad'],
        encodedLocations: '',
      };
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL, malformedTBData),
      ];

      await assert.rejects(
        compute.request({url}),
        new RegExp('TrustBoundary: Failure while getting trust boundaries:'),
      );
      scopes.forEach(s => s.done());
    });

    it('getRequestHeaders should attach a trust boundary header in case of valid tb', async () => {
      const compute = new Compute({serviceAccountEmail: SERVICE_ACCOUNT_EMAIL});
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL),
      ];

      const reqheaders = await compute.getRequestHeaders();

      assert.deepStrictEqual(
        reqheaders.get('x-allowed-locations'),
        EXPECTED_TB_DATA.encodedLocations,
      );
      scopes.forEach(s => s.done());
    });

    it('getRequestHeaders should attach an empty string TB header in case of no_op tb', async () => {
      const compute = new Compute({serviceAccountEmail: SERVICE_ACCOUNT_EMAIL});
      const scopes = [
        setupTokenNock(SERVICE_ACCOUNT_EMAIL),
        setupTrustBoundaryNock(SERVICE_ACCOUNT_EMAIL, NO_OP_TB_DATA),
      ];

      const reqheaders = await compute.getRequestHeaders();

      assert.deepStrictEqual(reqheaders.get('x-allowed-locations'), '');
      scopes.forEach(s => s.done());
    });

    it('getRequestHeaders should not attach TB header in case of non GDU universe', async () => {
      const compute = new Compute({
        serviceAccountEmail: SERVICE_ACCOUNT_EMAIL,
        universe_domain: 'abc.com',
      });
      const scopes = [setupTokenNock(SERVICE_ACCOUNT_EMAIL)];

      const reqheaders = await compute.getRequestHeaders();

      assert.deepStrictEqual(reqheaders.get('x-allowed-locations'), null);
      scopes.forEach(s => s.done());
    });
  });
});
