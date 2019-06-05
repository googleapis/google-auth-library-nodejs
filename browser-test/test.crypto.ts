/**
 * Copyright 2019 Google LLC. All Rights Reserved.
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

import * as base64js from 'base64-js';
import {assert} from 'chai';
import {createCrypto} from '../src/crypto/crypto';
import {BrowserCrypto} from '../src/crypto/browser/crypto';
import {privateKey, publicKey} from './fixtures/keys';

// Not all browsers support `TextEncoder`. The following `require` will
// provide a fast UTF8-only replacement for those browsers that don't support
// text encoding natively.
require('fast-text-encoding');

describe('Browser crypto tests', () => {
  const crypto = createCrypto();

  it('should create a BrowserCrypto instance', () => {
    assert(crypto instanceof BrowserCrypto);
  });

  it('should calculate SHA256 digest', async () => {
    const input = 'I can calculate SHA256';
    const expectedDigest = 'c9CEhti/1PtLwS3YkDYE3b3lrZW276VnvXI86BqIESI=';
    const calculatedDigest = await crypto.sha256DigestBase64(input);
    assert.strictEqual(calculatedDigest, expectedDigest);
  });

  it('should generate random bytes', () => {
    const requestedLength = 20;
    const generated1Base64 = crypto.randomBytesBase64(requestedLength);
    const generated1 = base64js.toByteArray(generated1Base64);
    assert.strictEqual(generated1.length, requestedLength);
    const generated2Base64 = crypto.randomBytesBase64(requestedLength);
    const generated2 = base64js.toByteArray(generated2Base64);
    assert.strictEqual(generated2.length, requestedLength);
    // random strings are random! let's just check they are different.
    // if they are the same, we have a problem.
    assert.notStrictEqual(generated1Base64, generated2Base64);
  });

  it('should verify a signature', async () => {
    const message = 'This message is signed';
    const signatureBase64 = [
      'BE1qD48LdssePdMmOhcanOd8V+i4yLSOL0H2EXNyy',
      'lCePnldIsLVqrOJnVkd0MUKxS/Y9B0te2tqlS8psP',
      'j9IWjcpiQeT9wUDRadxHIX26W6JHgSCOzOavpJCbh',
      'M3Kez7QEwbkrI54rYu7qgx/mmckxkC0vhg0Z5OQbO',
      'IXfILVs1ztNNdt9r/ZzNVxTMKhL3nHLfjVqG/LUGy',
      'RhFhjzLvIJAfL0CSEfycUvm6t5NVzF4SkZ8KKQ7wJ',
      'vLw492bRB/633GJOZ1prVjAUQUI64BXFrvRgWsxLK',
      'M0XtF5tNbC+eIDrH0LiMraAhcZwj1iWofH1h/dg3E',
      'xtU9UWfbed/yfw',
    ].join(''); // note: no padding
    const verified = await crypto.verify(publicKey, message, signatureBase64);
    assert(verified);
  });

  it('should sign a message', async () => {
    const message = 'This message is signed';
    const expectedSignatureBase64 = [
      'BE1qD48LdssePdMmOhcanOd8V+i4yLSOL0H2EXNyy',
      'lCePnldIsLVqrOJnVkd0MUKxS/Y9B0te2tqlS8psP',
      'j9IWjcpiQeT9wUDRadxHIX26W6JHgSCOzOavpJCbh',
      'M3Kez7QEwbkrI54rYu7qgx/mmckxkC0vhg0Z5OQbO',
      'IXfILVs1ztNNdt9r/ZzNVxTMKhL3nHLfjVqG/LUGy',
      'RhFhjzLvIJAfL0CSEfycUvm6t5NVzF4SkZ8KKQ7wJ',
      'vLw492bRB/633GJOZ1prVjAUQUI64BXFrvRgWsxLK',
      'M0XtF5tNbC+eIDrH0LiMraAhcZwj1iWofH1h/dg3E',
      'xtU9UWfbed/yfw==',
    ].join('');

    const signatureBase64 = await crypto.sign(privateKey, message);
    assert.strictEqual(signatureBase64, expectedSignatureBase64);
  });

  it('should decode unpadded base64', () => {
    const originalString = 'test string';
    const base64String = 'dGVzdCBzdHJpbmc';
    const decodedString = crypto.decodeBase64StringUtf8(base64String);
    assert.strictEqual(decodedString, originalString);
  });

  it('should encode to base64 and pad the result', () => {
    const originalString = 'test string';
    const base64String = 'dGVzdCBzdHJpbmc=';
    const encodedString = crypto.encodeBase64StringUtf8(originalString);
    assert.strictEqual(encodedString, base64String);
  });
});
