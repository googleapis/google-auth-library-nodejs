// Copyright 2022 Google LLC
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

const SAML_SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:saml2';
const OIDC_SUBJECT_TOKEN_TYPE1 = 'urn:ietf:params:oauth:token-type:id_token';
const OIDC_SUBJECT_TOKEN_TYPE2 = 'urn:ietf:params:oauth:token-type:jwt';

/**
 * Interface defining JSON format of response from 3rd party executable used by
 * pluggable auth client.
 */
export interface ExecutableResponseJson {
  /**
   * The version of the JSON response. Only version 1 is currently supported.
   * Always required.
   */
  version: number;
  /**
   * Whether the executable ran successfully. Always required.
   */
  success: boolean;
  /**
   * Epoch time for expiration of the token in seconds, required for successful
   * responses.
   */
  expiration_time?: number;
  /**
   * Type of subject token in the response, currently supported values are:
   * urn:ietf:params:oauth:token-type:saml2
   * urn:ietf:params:oauth:token-type:id_token
   * urn:ietf:params:oauth:token-type:jwt
   */
  token_type?: string;
  /**
   * Error code from executable, required when unsuccessful.
   */
  code?: string;
  /**
   * Error message from executable, required when unsuccessful.
   */
  message?: string;
  /**
   * ID token to be used as a subject token when token_type is id_token or jwt.
   */
  id_token?: string;
  /**
   * Response to be used as a subject token when token_type is saml2.
   */
  saml_response?: string;
}

/**
 * Defines the response of a 3rd party executable run by the pluggable auth client.
 */
export class ExecutableResponse {
  readonly version: number;
  readonly success: boolean;
  readonly expirationTime?: number;
  readonly tokenType?: string;
  readonly errorCode?: string;
  readonly errorMessage?: string;
  readonly subjectToken?: string;

  /**
   * Instantiates an ExecutableResponse instance using the provided JSON object
   * from the output of the executable.
   * @param responseJson Response from a 3rd party executable, loaded from a
   * run of the executable or a cached output file.
   */
  constructor(responseJson: ExecutableResponseJson) {
    // Check that always required fields exist in the json response.
    if (!responseJson.version) {
      throw Error("Executable response must contain a 'version' field.");
    }
    if (responseJson.success === undefined) {
      throw Error("Executable response must contain a 'success' field.");
    }

    this.version = responseJson.version;
    this.success = responseJson.success;

    // Validate required fields for a successful response.
    if (this.success) {
      if (!responseJson.expiration_time) {
        throw Error(
          "Executable response must contain an 'expiration_time' field when successful."
        );
      }
      if (!responseJson.token_type) {
        throw Error(
          "Executable response must contain a 'token_type' field when successful."
        );
      }
      this.expirationTime = responseJson.expiration_time;
      this.tokenType = responseJson.token_type;

      // Validate that token type and subject token value.
      if (this.tokenType === SAML_SUBJECT_TOKEN_TYPE) {
        if (!responseJson.saml_response) {
          throw Error(
            `Executable response must contain a 'saml_response' field when token_type=${SAML_SUBJECT_TOKEN_TYPE}.`
          );
        }
        this.subjectToken = responseJson.saml_response;
      } else if (
        this.tokenType === OIDC_SUBJECT_TOKEN_TYPE1 ||
        this.tokenType === OIDC_SUBJECT_TOKEN_TYPE2
      ) {
        if (!responseJson.id_token) {
          throw Error(
            "Executable response must contain a 'id_token' field when " +
              `token_type=${OIDC_SUBJECT_TOKEN_TYPE1} or ${OIDC_SUBJECT_TOKEN_TYPE2}.`
          );
        }
        this.subjectToken = responseJson.id_token;
      } else {
        throw Error(
          "Executable response must contain a 'token_type' field when successful " +
            `and it must be one of ${OIDC_SUBJECT_TOKEN_TYPE1}, ${OIDC_SUBJECT_TOKEN_TYPE2}, or ${SAML_SUBJECT_TOKEN_TYPE}.`
        );
      }
    } else {
      // Both code and message must be provided for unsuccessful responses.
      if (!responseJson.code || !responseJson.message) {
        throw Error(
          "Executable response must contain a 'code' and 'message' field when unsuccessful."
        );
      }
      this.errorCode = responseJson.code;
      this.errorMessage = responseJson.message;
    }
  }

  /**
   * @return A boolean representing if the response has a valid token. Returns
   * true when the response was successful and the token is not expired.
   */
  isValid(): boolean {
    return !this.isExpired() && this.success;
  }

  /**
   * @return A boolean representing if the response is expired. Returns true if
   * the expiration_time field was not provided or if the provided time has
   * passed.
   */
  isExpired(): boolean {
    return (
      !this.expirationTime ||
      this.expirationTime < Math.round(Date.now() / 1000)
    );
  }
}
