// Copyright 2021 Google LLC
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

import * as assert from 'assert';
import * as nock from 'nock';
import * as qs from 'querystring';
import {GetAccessTokenResponse} from '../src/auth/oauth2client';
import {OAuthErrorResponse} from '../src/auth/oauth2common';
import {StsSuccessfulResponse} from '../src/auth/stscredentials';
import {
  IamGenerateAccessTokenResponse,
  ProjectInfo,
} from '../src/auth/baseexternalclient';

interface CloudRequestError {
  error: {
    code: number;
    message: string;
    status: string;
  };
}

interface NockMockStsToken {
  statusCode: number;
  response: StsSuccessfulResponse | OAuthErrorResponse;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request: {[key: string]: any};
  additionalHeaders?: {[key: string]: string};
}

interface NockMockGenerateAccessToken {
  statusCode: number;
  token: string;
  response: IamGenerateAccessTokenResponse | CloudRequestError;
  scopes: string[];
}

const defaultProjectNumber = '123456';
const poolId = 'POOL_ID';
const providerId = 'PROVIDER_ID';
const baseUrl = 'https://sts.googleapis.com';
const path = '/v1/token';
const saEmail = 'service-1234@service-name.iam.gserviceaccount.com';
const saBaseUrl = 'https://iamcredentials.googleapis.com';
const saPath = `/v1/projects/-/serviceAccounts/${saEmail}:generateAccessToken`;

export function mockStsTokenExchange(
  nockParams: NockMockStsToken[]
): nock.Scope {
  const scope = nock(baseUrl);
  nockParams.forEach(nockMockStsToken => {
    const headers = Object.assign(
      {
        'content-type': 'application/x-www-form-urlencoded',
      },
      nockMockStsToken.additionalHeaders || {}
    );
    scope
      .post(path, qs.stringify(nockMockStsToken.request), {
        reqheaders: headers,
      })
      .reply(nockMockStsToken.statusCode, nockMockStsToken.response);
  });
  return scope;
}

export function mockGenerateAccessToken(
  nockParams: NockMockGenerateAccessToken[]
): nock.Scope {
  const scope = nock(saBaseUrl);
  nockParams.forEach(nockMockGenerateAccessToken => {
    const token = nockMockGenerateAccessToken.token;
    scope
      .post(
        saPath,
        {
          scope: nockMockGenerateAccessToken.scopes,
        },
        {
          reqheaders: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      )
      .reply(
        nockMockGenerateAccessToken.statusCode,
        nockMockGenerateAccessToken.response
      );
  });
  return scope;
}

export function getAudience(
  projectNumber: string = defaultProjectNumber
): string {
  return (
    `//iam.googleapis.com/projects/${projectNumber}` +
    `/locations/global/workloadIdentityPools/${poolId}/` +
    `providers/${providerId}`
  );
}

export function getTokenUrl(): string {
  return `${baseUrl}${path}`;
}

export function getServiceAccountImpersonationUrl(): string {
  return `${saBaseUrl}${saPath}`;
}

export function assertGaxiosResponsePresent(resp: GetAccessTokenResponse) {
  const gaxiosResponse = resp.res || {};
  assert('data' in gaxiosResponse && 'status' in gaxiosResponse);
}

export function mockCloudResourceManager(
  projectNumber: string,
  accessToken: string,
  statusCode: number,
  response: ProjectInfo | CloudRequestError
): nock.Scope {
  return nock('https://cloudresourcemanager.googleapis.com')
    .get(`/v1/projects/${projectNumber}`, undefined, {
      reqheaders: {
        Authorization: `Bearer ${accessToken}`,
      },
    })
    .reply(statusCode, response);
}
