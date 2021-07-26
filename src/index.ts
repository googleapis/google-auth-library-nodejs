// Copyright 2017 Google LLC
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
import {GoogleAuth} from './auth/googleauth';

export {Compute, ComputeOptions} from './auth/computeclient';
export {
  CredentialBody,
  CredentialRequest,
  Credentials,
  JWTInput,
} from './auth/credentials';
export {GCPEnv} from './auth/envDetect';
export {GoogleAuthOptions, ProjectIdCallback} from './auth/googleauth';
export {IAMAuth, RequestMetadata} from './auth/iam';
export {IdTokenClient, IdTokenProvider} from './auth/idtokenclient';
export {Claims, JWTAccess} from './auth/jwtaccess';
export {JWT, JWTOptions} from './auth/jwtclient';
export {
  Certificates,
  CodeChallengeMethod,
  CodeVerifierResults,
  GenerateAuthUrlOpts,
  GetTokenOptions,
  OAuth2Client,
  OAuth2ClientOptions,
  RefreshOptions,
  TokenInfo,
  VerifyIdTokenOptions,
} from './auth/oauth2client';
export {LoginTicket, TokenPayload} from './auth/loginticket';
export {
  UserRefreshClient,
  UserRefreshClientOptions,
} from './auth/refreshclient';
export {AwsClient, AwsClientOptions} from './auth/awsclient';
export {
  IdentityPoolClient,
  IdentityPoolClientOptions,
} from './auth/identitypoolclient';
export {
  ExternalAccountClient,
  ExternalAccountClientOptions,
} from './auth/externalclient';
export {
  BaseExternalAccountClient,
  BaseExternalAccountClientOptions,
} from './auth/baseexternalclient';
export {DefaultTransporter} from './transporters';

const auth = new GoogleAuth();
export {auth, GoogleAuth};
