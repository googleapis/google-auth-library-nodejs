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

var url = require('url');
var queryString = require('querystring');
var assert = require('assert');
var pick = require('lodash.pick');
var urlUtils = require('../lib/transports/http/url.js');


describe('HTTP wrapper utils -- url utils', function () {
  describe('extractUrlComponents', function () {
    describe('Given an invalid url object', function () {
      it('should throw', function () {
        assert.throws(function () {
          urlUtils.extractUrlComponents({
            urlObject: {
              host: 'x',
              path: 'y'
            }
          });
        });
      });
    });
    describe('Given a valid url object', function () {
      it('Should extract host and path', function () {
        var urlObj = url.parse('http://www.example.com/test/path/');
        var out = urlUtils.extractUrlComponents({urlObject: urlObj});
        assert.deepEqual({requestOptions: pick(urlObj, ['host', 'path'])},
          pick(out, ['requestOptions']));
      });
    });
    describe('Given a valid object with queryString params', function () {
      var qs = {test: true};
      var href = 'http://www.example.com/path';
      var urlObj = url.parse(href);
      var GENERATED_OPTIONS = {
        hasBody: false,
        urlObject: urlObj,
        requestPayload: {
          isJSON: false,
          queryString: queryString.stringify(qs)
        }
      };
      it('Should return the path with the queryString appended', function () {
        var out = urlUtils.extractUrlComponents(GENERATED_OPTIONS);
        assert.strictEqual(out.requestOptions.host, urlObj.host);
        assert.strictEqual(out.requestOptions.path,
          urlObj.path+'?'+queryString.stringify(qs));
      });
    });
  });
  describe('isUsingHttps', function () {
    describe('Given an invalid url object', function () {
      it('Should throw', function () {
        assert.throws(function () {
          urlUtils.isUsingHttps({urlObject: {protocol: 'https'}});
        });
      });
    });
    describe('Given a valid url object', function () {
      describe('Given the string https as protocol', function () {
        it('Should return a prop "isUsingHttps" set to true', function () {
          var obj = url.parse('https://www.example.com/get');
          var out = urlUtils.isUsingHttps({urlObject: obj});
          assert.deepEqual({isUsingHttps: true}, pick(out, 'isUsingHttps'));
        });
      });
      describe('Given the string http as protocol', function () {
        it('Should return a prop "isUsingHttps" set to false', function () {
          var obj = url.parse('http://www.example.com/get');
          var out = urlUtils.isUsingHttps({urlObject: obj});
          assert.deepEqual({isUsingHttps: false}, pick(out, 'isUsingHttps'));
        });
      });
    });
  });
  describe('extractRawHref', function () {
    var HREF = 'https://example.io/post';
    it('Should extract the href if given via the "uri" prop', function () {
      assert.deepEqual(urlUtils.extractRawHref({}, {uri: HREF}), {href: HREF});
    });
    it('Should extract the href if given via the "url" prop', function () {
      assert.deepEqual(urlUtils.extractRawHref({}, {url: HREF}), {href: HREF});
    });
    it('Should set href as null if not given a known prop', function () {
      assert.deepEqual(urlUtils.extractRawHref({}, {path: HREF}), {href: null});
    });
  });
  describe('createUrlObject', function () {
    var HREF = 'https://example.io/get';
    describe('Given an invalid type for href', function () {
      it('should throw', function () {
        assert.throws(function () {
          urlUtils.createUrlObject({href: {url: 'x', path: 'y'}});
        });
      });
    });
    describe('Given a string for href', function () {
      it('Should set a Url object on the prop urlObject', function () {
        assert.deepEqual(
          pick(urlUtils.createUrlObject({href: HREF}), 'urlObject'),
          {urlObject: url.parse(HREF)}
        );
      });
    });
  });
  describe('generateUrl', function () {
    describe('Given a valid set of generated and given options', function () {
      var GENERATED_OPTIONS = {};
      var GIVEN_OPTIONS = {url: 'https://abc.org/a/get/path?with=queryString'};
      var PARSED_URL = url.parse(GIVEN_OPTIONS.url);
      it('Should return a populated options object', function () {
        assert.deepEqual(
          urlUtils.generateUrl(GENERATED_OPTIONS, GIVEN_OPTIONS),
          {
            isUsingHttps: true,
            href: GIVEN_OPTIONS.url,
            urlObject: PARSED_URL,
            requestOptions: {
              host: PARSED_URL.host,
              path: PARSED_URL.path
            }
          }
        );
      });
    });
  });
});
