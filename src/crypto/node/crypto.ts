// Copyright 2019 Google LLC
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

import * as crypto from 'crypto';
import {Crypto} from '../crypto';
import * as base64js from 'base64-js';

interface WebCryptoInterface {
  subtle: {
    digest: Function;
    importKey: Function;
    verify: Function;
    sign: Function;
  };
  getRandomValues: Function;
}

const webcrypto = (crypto as any).webcrypto as WebCryptoInterface;

export class NodeCrypto implements Crypto {
  async sha256DigestBase64(str: string): Promise<string> {
    const inputBuffer = new TextEncoder().encode(str);

    // Result is ArrayBuffer as well.
    const outputBuffer = await webcrypto.subtle.digest('SHA-256', inputBuffer);

    return base64js.fromByteArray(new Uint8Array(outputBuffer));
  }

  randomBytesBase64(count: number): string {
    const array = new Uint8Array(count);
    webcrypto.getRandomValues(array);
    return base64js.fromByteArray(array);
  }

  private static padBase64(base64: string): string {
    // base64js requires padding, so let's add some '='
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return base64;
  }

  async verify(
    pubkey: string,
    data: string,
    signature: string
  ): Promise<boolean> {
    const algo = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {name: 'SHA-256'},
    };

    // eslint-disable-next-line node/no-unsupported-features/node-builtins
    const dataArray = new TextEncoder().encode(data);
    const signatureArray = base64js.toByteArray(
      NodeCrypto.padBase64(signature)
    );
    const ko = (crypto as any).createPublicKey(pubkey, 'pem', 'pkcs1');
    const cryptoKey = await webcrypto.subtle.importKey(
      'node.keyObject',
      ko,
      algo,
      true,
      ['verify']
    );
    // SubtleCrypto's verify method is async so we must make
    // this method async as well.
    const result = await webcrypto.subtle.verify(
      algo,
      cryptoKey,
      signatureArray,
      dataArray
    );
    return result;
  }

  async sign(privateKey: string, data: string | Buffer): Promise<string> {
    const algo = {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {name: 'SHA-256'},
    };
    // eslint-disable-next-line node/no-unsupported-features/node-builtins
    const dataArray = new TextEncoder().encode(
      Buffer.from(data).toString('utf8')
    );
    const ko = (crypto as any).createPrivateKey(privateKey, 'pem', 'pkcs1');
    const cryptoKey = await webcrypto.subtle.importKey(
      'node.keyObject',
      ko,
      algo,
      true,
      ['sign']
    );

    // SubtleCrypto's sign method is async so we must make
    // this method async as well.
    const result = await webcrypto.subtle.sign(algo, cryptoKey, dataArray);
    return base64js.fromByteArray(new Uint8Array(result));
  }

  decodeBase64StringUtf8(base64: string): string {
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  encodeBase64StringUtf8(text: string): string {
    return Buffer.from(text, 'utf-8').toString('base64');
  }
}
