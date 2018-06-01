import * as crypto from 'crypto';
import {Crypto} from '../crypto';

export class NodeCrypto implements Crypto {
  sha256DigestBase64(str: string): Promise<string> {
    return Promise.resolve(
        crypto.createHash('sha256').update(str).digest('base64'));
  }

  randomBytesBase64(count: number): string {
    return crypto.randomBytes(count).toString('base64');
  }
}
