// Copyright 2023 Google LLC
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

import {strict as assert} from 'assert';
import {AuthClient} from '../src';
import {GaxiosPromise} from 'gaxios';

describe('static', () => {
  describe('normalize', () => {
    it('should accept and normalize `AuthClient`', async () => {
      class MyAuthClient extends AuthClient {
        getRequestHeaders = async () => ({});
        getAccessToken = async () => ({});

        request<T>(): GaxiosPromise<T> {
          return {} as GaxiosPromise<T>;
        }
      }

      const authClient = new MyAuthClient();
      const auth = AuthClient.normalize(authClient);

      assert.equal(auth, authClient);
    });

    it('should accept and normalize `AuthClientLike`', async () => {
      const authClientLike = {request: async () => ({})};
      const auth = AuthClient.normalize(authClientLike);

      assert.equal(auth, authClientLike);
    });
  });
});
