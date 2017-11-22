import {AxiosRequestConfig} from 'axios';

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

// tslint:disable-next-line no-any
export function validate(options: any) {
  const vpairs = [
    {invalid: 'uri', expected: 'url'}, {invalid: 'json', expected: 'data'},
    {invalid: 'qs', expected: 'params'}
  ];
  for (const pair of vpairs) {
    if (options[pair.invalid]) {
      const e = `'${
          pair.invalid}' is not a valid configuration option. Please use '${
          pair.expected}' instead. This library is using Axios for requests. Please see https://github.com/axios/axios to learn more about the valid request options.`;
      throw new Error(e);
    }
  }
}
