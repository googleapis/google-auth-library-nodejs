"use strict";
exports.__esModule = true;
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
var assert = require("assert");
var googleauth_1 = require("../lib/auth/googleauth");
var transporters_1 = require("../lib/transporters");
describe('module', function () {
    it('should export GoogleAuth as a function', function () {
        var cjs = require('../');
        assert.strictEqual(typeof cjs, 'function');
        assert.strictEqual(cjs, googleauth_1.GoogleAuth);
    });
    it('should publicly export DefaultTransporter', function () {
        var cjs = require('../');
        assert.strictEqual(cjs.DefaultTransporter, transporters_1.DefaultTransporter);
    });
});
