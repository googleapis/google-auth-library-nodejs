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

import * as assert from 'assert';
import {GaxiosOptions} from 'gaxios';
const assertRejects = require('assert-rejects');
import * as nock from 'nock';
import {DefaultTransporter, RequestError} from '../src/transporters';

const savedEnv = process.env;
afterEach(() => {
  process.env = savedEnv;
});

nock.disableNetConnect();

const defaultUserAgentRE = 'google-auth-library-nodejs/\\d+.\\d+.\\d+';
const transporter = new DefaultTransporter();

it('should set default adapter to node.js', () => {
  const opts = transporter.configure();
  const re = new RegExp(defaultUserAgentRE);
  assert(re.test(opts.headers!['User-Agent']));
});

it('should append default client user agent to the existing user agent', () => {
  const applicationName = 'MyTestApplication-1.0';
  const opts = transporter.configure({
    headers: {'User-Agent': applicationName},
    url: '',
  });
  const re = new RegExp(applicationName + ' ' + defaultUserAgentRE);
  assert(re.test(opts.headers!['User-Agent']));
});

it('should not append default client user agent to the existing user agent more than once', () => {
  const appName = 'MyTestApplication-1.0 google-auth-library-nodejs/foobear';
  const opts = transporter.configure({
    headers: {'User-Agent': appName},
    url: '',
  });
  assert.strictEqual(opts.headers!['User-Agent'], appName);
});

it('should respect an empty User-Agent, and drop the value from headers', () => {
  const opts = transporter.configure({
    headers: {'User-Agent': null},
    url: '',
  });
  assert.strictEqual(opts.headers!.hasOwnProperty('User-Agent'), false);
});

it('should respect empty', () => {
  const appName = 'MyTestApplication-1.0 google-auth-library-nodejs/foobear';
  const opts = transporter.configure({
    headers: {'User-Agent': appName},
    url: '',
  });
  assert.strictEqual(opts.headers!['User-Agent'], appName);
});

it('should create a single error from multiple response errors', done => {
  const firstError = {message: 'Error 1'};
  const secondError = {message: 'Error 2'};
  const url = 'http://example.com';
  const scope = nock(url)
    .get('/')
    .reply(400, {error: {code: 500, errors: [firstError, secondError]}});
  transporter.request({url}, error => {
    scope.done();
    assert.strictEqual(error!.message, 'Error 1\nError 2');
    assert.strictEqual((error as RequestError).code, 500);
    assert.strictEqual((error as RequestError).errors.length, 2);
    done();
  });
});

it('should return an error for a 404 response', done => {
  const url = 'http://example.com';
  const scope = nock(url)
    .get('/')
    .reply(404, 'Not found');
  transporter.request({url}, error => {
    scope.done();
    assert.strictEqual(error!.message, 'Not found');
    assert.strictEqual((error as RequestError).code, '404');
    done();
  });
});

it('should return an error if you try to use request config options', done => {
  const expected =
    "'uri' is not a valid configuration option. Please use 'url' instead. This library is using Axios for requests. Please see https://github.com/axios/axios to learn more about the valid request options.";
  transporter.request(
    {
      uri: 'http://example.com/api',
    } as GaxiosOptions,
    error => {
      assert.strictEqual(error!.message, expected);
      done();
    }
  );
});

it('should return an error if you try to use request config options with a promise', async () => {
  const expected = new RegExp(
    `'uri' is not a valid configuration option. Please use 'url' instead. This ` +
      `library is using Axios for requests. Please see https://github.com/axios/axios ` +
      `to learn more about the valid request options.`
  );
  const uri = 'http://example.com/api';
  assert.throws(() => transporter.request({uri} as GaxiosOptions), expected);
});

it('should support invocation with async/await', async () => {
  const url = 'http://example.com';
  const scope = nock(url)
    .get('/')
    .reply(200);
  const res = await transporter.request({url});
  scope.done();
  assert.strictEqual(res.status, 200);
});

it('should throw if using async/await', async () => {
  const url = 'http://example.com';
  const scope = nock(url)
    .get('/')
    .reply(500, '🦃');
  await assertRejects(transporter.request({url}), /🦃/);
  scope.done();
});

it('should work with a callback', done => {
  const url = 'http://example.com';
  const scope = nock(url)
    .get('/')
    .reply(200);
  transporter.request({url}, (err, res) => {
    scope.done();
    assert.strictEqual(err, null);
    assert.strictEqual(res!.status, 200);
    done();
  });
});

// tslint:disable-next-line ban
it.skip('should use the https proxy if one is configured', async () => {
  process.env['https_proxy'] = 'https://han:solo@proxy-server:1234';
  const transporter = new DefaultTransporter();
  const scope = nock('https://proxy-server:1234')
    .get('https://example.com/fake', undefined, {
      reqheaders: {
        host: 'example.com',
        accept: /.*/g,
        'user-agent': /google-api-nodejs-client\/.*/g,
        'proxy-authorization': /.*/g,
      },
    })
    .reply(200);
  const url = 'https://example.com/fake';
  const result = await transporter.request({url});
  scope.done();
  assert.strictEqual(result.status, 200);
});
