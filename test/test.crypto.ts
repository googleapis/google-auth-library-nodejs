import * as fs from 'fs';
import {assert} from 'chai';
import {createCrypto} from '../src/crypto/crypto';
import {NodeCrypto} from '../src/crypto/node/crypto';

const publicKey = fs.readFileSync('./test/fixtures/public.pem', 'utf-8');
const privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');

describe('Node.js crypto tests', () => {
  const crypto = createCrypto();

  it('should create a NodeCrypto instance', () => {
    assert(crypto instanceof NodeCrypto);
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
    const generated1 = Buffer.from(generated1Base64, 'base64');
    assert.strictEqual(generated1.length, requestedLength);
    const generated2Base64 = crypto.randomBytesBase64(requestedLength);
    const generated2 = Buffer.from(generated2Base64, 'base64');
    assert.strictEqual(generated2.length, requestedLength);
    // random strings are random! let's just check they are different.
    // if they are the same, we have a problem.
    assert.notStrictEqual(generated1Base64, generated2Base64);
  });

  it('should verify a signature', async () => {
    const message = 'This message is signed';
    const signatureBase64 = [
      'ufyKBV+Ar7Yq8CSmSIN9m38ch4xnWBz8CP4qHh6V+',
      'm4cCbeXdR1MEmWVhNJjZQFv3KL3tDAnl0Q4bTcSR/',
      'mmhXaRjdxyJ6xAUp0KcbVq6xsDIbnnYHSgYr3zVoS',
      'dRRefWSWTknN1S69fNmKEfUeBIJA93xitr3pbqtLC',
      'bP28XNU',
    ].join(''); // note: no padding
    const verified = await crypto.verify(publicKey, message, signatureBase64);
    assert(verified);
  });

  it('should sign a message', async () => {
    const message = 'This message is signed';
    const expectedSignatureBase64 = [
      'ufyKBV+Ar7Yq8CSmSIN9m38ch4xnWBz8CP4qHh6V+',
      'm4cCbeXdR1MEmWVhNJjZQFv3KL3tDAnl0Q4bTcSR/',
      'mmhXaRjdxyJ6xAUp0KcbVq6xsDIbnnYHSgYr3zVoS',
      'dRRefWSWTknN1S69fNmKEfUeBIJA93xitr3pbqtLC',
      'bP28XNU=',
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

  it('should not load fast-text-encoding while running in nodejs', () => {
    const loadedModules = Object.keys(require('module')._cache);
    const hits = loadedModules.filter(x => x.includes('fast-text-encoding'));
    assert.strictEqual(hits.length, 0);
  });
});
