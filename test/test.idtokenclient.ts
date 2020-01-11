
import * as assert from 'assert';
import {it} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';

import {IdTokenClient, JWT} from '../src';
import {CredentialRequest} from '../src/auth/credentials';

const keypair = require('keypair');

nock.disableNetConnect();

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, body);
}

let sandbox: sinon.SinonSandbox;
beforeEach(() => {
  sandbox = sinon.createSandbox();
});

afterEach(() => {
  nock.cleanAll();
  sandbox.restore();
});

it('should determine expiry_date from JWT', async () => {
  const keys = keypair(1024 /* bitsize of private key */);
  const idToken = 'header.eyJleHAiOiAxNTc4NzAyOTU2fQo.signature'
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com',
  });

  const scope = createGTokenMock({id_token: idToken});
  const targetAudience = 'a-target-audience'
  const client = new IdTokenClient({idTokenProvider: jwt, targetAudience});
  await client.getRequestHeaders();
  scope.done();
  assert.strictEqual(client.credentials.expiry_date, 1578702956000);
});

it('should refresh ID token if expired', async() => {
  const keys = keypair(1024 /* bitsize of private key */);
  const jwt = new JWT({
    email: 'foo@serviceaccount.com',
    key: keys.private,
    subject: 'ignored@subjectaccount.com',
  });

  const scope = createGTokenMock({id_token: 'abc123'});
  const targetAudience = 'a-target-audience'
  const client = new IdTokenClient({idTokenProvider: jwt, targetAudience});
  client.credentials = {
    id_token: 'an-identity-token',
    expiry_date: new Date().getTime() - 1000,
  };
  await client.getRequestHeaders();
  scope.done();
  assert.strictEqual(client.credentials.id_token, 'abc123');
});
