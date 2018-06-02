/**
 * Copyright 2018 Google Inc. All Rights Reserved.
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

// This file implements crypto functions we need using in-browser
// SubtleCrypto interface `window.crypto.subtle`.

import * as base64js from 'base64-js';
import * as TextEncoding from 'text-encoding-shim';

import {Crypto, JwkCertificate} from '../crypto';

export class BrowserCrypto implements Crypto {
  sha256DigestBase64(str: string): Promise<string> {
    return new Promise(resolve => {
      window.crypto.subtle
          .digest('SHA-256', new TextEncoding.TextEncoder().encode(str))
          .then(
              arrayBuffer =>
                  resolve(base64js.fromByteArray(new Uint8Array(arrayBuffer))));
    });
  }

  randomBytesBase64(count: number): string {
    const array = new Uint8Array(count);
    window.crypto.getRandomValues(array);
    return base64js.fromByteArray(array);
  }

  verify(pubkey: JwkCertificate, data: string, signature: string):
      Promise<boolean> {
    return new Promise(resolve => {
      const algo = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: {name: 'SHA-256'},
      };
      const dataArray = new TextEncoding.TextEncoder().encode(data);
      // base64js requires padding, so let's add some '='
      while (signature.length % 4 !== 0) {
        signature += '=';
      }
      const signatureArray = base64js.toByteArray(signature);
      window.crypto.subtle.importKey('jwk', pubkey, algo, true, ['verify'])
          .then(ck => {
            window.crypto.subtle.verify(algo, ck, signatureArray, dataArray)
                .then(resolve);
          });
    });
  }
}
