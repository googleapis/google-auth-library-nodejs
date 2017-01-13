/**
 * Copyright 2016 Google Inc. All Rights Reserved.
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

'use strict';

var assert = require('assert');
var merge = require('lodash.merge');
var headers = require('../lib/transports/http/headers.js');

describe('HTTP wrapper utils -- headers utils', function () {
  describe('extractGivenHeaders', function () {
    var extractGivenHeaders = headers.extractGivenHeaders;
    describe('Given pre-existing headers', function () {
      it('Should preserve in output', function () {
        var GIVEN_OPTIONS = {headers: {'Custom-Header': '1.x'}};
        assert.deepEqual(extractGivenHeaders({}, GIVEN_OPTIONS),
          {requestOptions: {headers: GIVEN_OPTIONS.headers}});
      });
    });
    describe('Given no pre-existing headers', function () {
      it('Should return an unmodified object as output', function () {
        var GIVEN_OPTIONS = {};
        assert.deepEqual(extractGivenHeaders({}, GIVEN_OPTIONS), {});
      });
    });
  });
  describe('addUserAgentHeaders', function () {
    var addUserAgentHeaders = headers.addUserAgentHeaders;
    it('Should add the user agent info to the headers object', function () {
      assert.deepEqual(
        addUserAgentHeaders({}),
        {
          requestOptions: {
            headers: {
              'User-Agent': headers.USER_AGENT
            }
          }
        }
      );
    });
  });
  describe('addRequestMethod', function () {
    var addRequestMethod = headers.addRequestMethod;
    describe('If the given method is not a string', function () {
      var DEFAULT_METHOD = 'GET';
      it('should default to '+DEFAULT_METHOD, function () {
        assert.deepEqual(
          addRequestMethod({}, {method: ['a_invalid_method']}),
          {requestOptions: {method: DEFAULT_METHOD}}
        );
      });
    });
    describe('If the given method is a string', function () {
      describe('Given an upper-case string', function () {
        var METHOD = 'POST';
        it('Should return the string unmodified', function () {
          assert.deepEqual(
            addRequestMethod({}, {method: METHOD}),
            {requestOptions: {method: METHOD}}
          );
        });
      });
      describe('Given a lower-case string', function () {
        var METHOD = 'put';
        it('Should return the string uppercased', function () {
          assert.deepEqual(
            addRequestMethod({}, {method: METHOD}),
            {requestOptions: {method: METHOD.toUpperCase()}}
          );
        });
      });
    });
  });
  describe('addPostMethodHeaders', function () {
    var addPostMethodHeaders = headers.addPostMethodHeaders;
    describe('Given a HTTP method which does not spec a body', function () {
      it('Should set the prop "hasBody" prop to false on output', function () {
        var METHOD = 'GET';
        assert.deepEqual(addPostMethodHeaders({requestOptions:{method: METHOD}}),
          {hasBody: false, requestOptions: {method: METHOD}});
      });
    });
    describe('Given a HTTP method which specs a body', function () {
      describe('A JSON body', function () {
        var GENERATED_OPTIONS = {
          requestOptions: {
            method: 'POST',
            headers: {
              'Another-Header': 'xyz'
            }
          },
          requestPayload: {
            isJSON: true,
            payload: '{"test": true}'
          }
        };
        var EXPECTED_GENERATED_CONTENT_HEADERS = {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(
            GENERATED_OPTIONS.requestPayload.payload)
        };
        var out = addPostMethodHeaders(GENERATED_OPTIONS);
        it('Should return a object with hasBody set to true', function () {
          assert.strictEqual(out.hasBody, true);
        });
        it('Should return a headers object with content info', function () {
          assert.deepEqual(
            out.requestOptions.headers,
            merge({}, {headers: GENERATED_OPTIONS.requestOptions.headers},
              {headers: EXPECTED_GENERATED_CONTENT_HEADERS}).headers
          );
        });
      });
      describe('A form body', function () {
        var GENERATED_OPTIONS = {
          requestOptions: {
            method: 'PUT',
            headers: {
              'Another-Header': 'abc'
            }
          },
          requestPayload: {
            isJSON: false,
            payload: '?test=false'
          },
        };
        var EXPECTED_GENERATED_CONTENT_HEADERS = {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(
            GENERATED_OPTIONS.requestPayload.payload)
        };
        var out = addPostMethodHeaders(GENERATED_OPTIONS);
        it('Should return a object with hasBody set to true', function () {
          assert.strictEqual(out.hasBody, true);
        });
        it('Should return a headers object with content info', function () {
          assert.deepEqual(
            out.requestOptions.headers,
            merge({}, {headers: GENERATED_OPTIONS.requestOptions.headers},
              {headers: EXPECTED_GENERATED_CONTENT_HEADERS}).headers
          );
        });
      });
    });
  });
  describe('generateHeaders', function () {
    var generateHeaders = headers.generateHeaders;
    var payload = '{"json": true}';
    var EXPECTED_GENERATED_CONTENT_HEADERS = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    };
    var GIVEN_OPTIONS = {
      method: 'PATCH',
      headers: {
        'Metadata-Flavor': 'spicy'
      }
    };
    var GENERATED_OPTIONS = {
      requestPayload: {
        isJSON: true,
        payload: payload
      }
    };
    var out = generateHeaders(GENERATED_OPTIONS, GIVEN_OPTIONS);
    it('Should set hasBody to true', function () {
      assert.strictEqual(out.hasBody, true);
    });
    it('Should generate a requestOptions object', function () { 
      assert.deepEqual(
        merge(
          {
            requestOptions: {
              method: GIVEN_OPTIONS.method,
              headers: GIVEN_OPTIONS.headers
            }
          },
          {requestOptions: {headers: {'User-Agent': headers.USER_AGENT}}},
          {requestOptions: {headers: EXPECTED_GENERATED_CONTENT_HEADERS}}
        ).requestOptions,
        out.requestOptions
      );
    });
  });
});
