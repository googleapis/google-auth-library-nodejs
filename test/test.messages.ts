/**
 * Copyright 2019 Google Inc. All Rights Reserved.
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
import * as assert from 'assert';
import * as messages from '../src/messages';
import * as sinon from 'sinon';

const warning1 = {
  code: 'google-auth-library:99998',
  type: messages.WarningTypes.WARNING,
  message: 'test warning 1',
};

const warning2 = {
  code: 'google-auth-library:99999',
  type: messages.WarningTypes.WARNING,
  message: 'test warning 2',
};

it('should warn', () => {
  const sandbox = sinon.createSandbox();
  let count = 0;
  sandbox.stub(process, 'emitWarning').callsFake(() => count++);
  messages.warn(warning1);
  assert.strictEqual(count, 1);
  sandbox.restore();
});

it('should warn just once', () => {
  const sandbox = sinon.createSandbox();
  let count = 0;
  sandbox.stub(process, 'emitWarning').callsFake(() => count++);
  messages.warn(warning2);
  messages.warn(warning2);
  messages.warn(warning2);
  assert.strictEqual(count, 1);
  sandbox.restore();
});
