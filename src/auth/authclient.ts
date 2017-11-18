/**
 * Copyright 2012 Google Inc. All Rights Reserved.
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

import axios, {AxiosPromise, AxiosRequestConfig, AxiosResponse} from 'axios';

import {DefaultTransporter} from '../transporters';

import {Credentials} from './credentials';

export interface BodyResponse {
  // tslint:disable-next-line no-any
  body: any;
  res?: AxiosResponse|null;
}

export abstract class AuthClient {
  transporter = new DefaultTransporter();
  credentials: Credentials;

  /**
   * Provides an alternative request
   * implementations with auth credentials.
   */
  abstract request(opts: AxiosRequestConfig): Promise<BodyResponse>;
}
