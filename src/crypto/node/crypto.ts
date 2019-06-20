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

import * as crypto from 'crypto';
import {Crypto} from '../crypto';

export class NodeCrypto implements Crypto {
  async sha256DigestBase64(str: string): Promise<string> {
    return crypto
      .createHash('sha256')
      .update(str)
      .digest('base64');
  }

  randomBytesBase64(count: number): string {
    return crypto.randomBytes(count).toString('base64');
  }

  async verify(
    pubkey: string,
    data: string | Buffer,
    signature: string
  ): Promise<boolean> {
    const verifier = crypto.createVerify('sha256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(pubkey, signature, 'base64');
  }

  async sign(privateKey: string, data: string | Buffer): Promise<string> {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(data);
    signer.end();
    return signer.sign(privateKey, 'base64');
  }

  decodeBase64StringUtf8(base64: string): string {
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  encodeBase64StringUtf8(text: string): string {
    return Buffer.from(text, 'utf-8').toString('base64');
  }
}
