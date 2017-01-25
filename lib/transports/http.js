/**
 * Copyright 2017 Google Inc. All Rights Reserved.
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

var url = require('./http/url');
var headers = require('./http/headers');
var payload = require('./http/payload');
var utils = require('./http/utils/http.js');

function formulateRequest (generatedOptions, cb) {
  var body = '';
  var request = utils.getTransport(generatedOptions.isUsingHttps).request(
    generatedOptions.requestOptions, function (response) {
      response.on('data', function (chunk) {
        body += chunk;
      });
      response.on('end', function () {
        cb(null, response, body);
      });
    }
  );
  request.on('error', function (err) {
    cb(err, null, null);
  });
  if (generatedOptions.hasBody) {
    request.write(generatedOptions.requestPayload.payload);
  }
  request.end();
  return request;
}

function request (givenOptions, cb) {
  return formulateRequest(
    url(
      headers(
        payload({}, givenOptions),
        givenOptions
      ),
      givenOptions
    ),
    utils.wrapGivenCallback(cb)
  );
}

module.exports = {
  request: request
};
