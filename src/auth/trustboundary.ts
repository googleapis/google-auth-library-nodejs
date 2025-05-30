// Copyright 2025 Google LLC
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

import {AuthClient, DEFAULT_UNIVERSE} from './authclient';
import {GaxiosError, GaxiosOptions, GaxiosResponse} from 'gaxios';

/**
 * value indicating no trust boundaries enforced
 **/
export const NoOpEncodedLocations = '0x0';

export const SERVICE_ACCOUNT_LOOKUP_ENDPOINT =
  'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_email}/allowedLocations';

export const WORKLOAD_LOOKUP_ENDPOINT =
  'https://iamcredentials.googleapis.com/v1/projects/{project_id}/locations/global/workloadIdentityPools/{pool_id}/allowedLocations';

export const WORKFORCE_LOOKUP_ENDPOINT =
  'https://iamcredentials.googleapis.com/v1/locations/global/workforcePools/{pool_id}/allowedLocations';

/**
 * Holds trust boundary related information like locations
 * where the credentials can be used.
 */
export interface TrustBoundaryData {
  /**
   * The readable text format of the allowed trust boundary locations.
   * This is optional, as it might not be present if no trust boundary is enforced.
   */
  locations?: string[];

  /**
   * The encoded text format of allowed trust boundary locations.
   * Expected to always be present in valid responses.
   */
  encodedLocations: string;
}

export interface TrustBoundaryProvider {
  fetchTrustBoundary: (authHeader: string) => Promise<TrustBoundaryData | null>;
}

/**
 * Internal helper function to fetch trust boundary data from a specific URL.
 *
 * @param authenticatedClient An authenticated AuthClient instance.
 * @param url The specific URL to fetch data from.
 * @returns A Promise resolving to a new TrustBoundary instance.
 * @throws {Error} If the request fails or the response is invalid.
 * @internal
 */
async function _fetchTrustBoundaryData(
  authenticatedClient: AuthClient,
  authHeader: string,
  url: string,
): Promise<TrustBoundaryData> {
  const requestOptions: GaxiosOptions = {
    method: 'GET',
    url: url,
    timeout: 5000,
  };
  requestOptions.headers = new Headers();
  requestOptions.headers.set('authorization', authHeader);

  try {
    const response: GaxiosResponse<TrustBoundaryData> =
      await authenticatedClient.transporter.request<TrustBoundaryData>(
        requestOptions,
      );
    if (response.status === 200 && response.data) {
      const trustBoundaryData = response.data;

      // Basic validation of the response structure
      if (typeof trustBoundaryData.encodedLocations !== 'string') {
        throw new Error(
          'TrustBoundary: Invalid response format - missing or invalid encodedLocations',
        );
      }

      return trustBoundaryData;
    } else {
      // Handle unexpected non-error statuses (though gaxios usually throws for >=400)
      throw new Error(
        `TrustBoundary: Request failed with status ${response.status}`,
      );
    }
  } catch (error) {
    if (error instanceof GaxiosError) {
      throw new Error(
        `TrustBoundary: API request failed with status ${error.response?.status}: ${error.message}`,
        {cause: error},
      );
    } else {
      throw new Error(
        `TrustBoundary: An unknown error occurred during fetch: ${error}`,
        {cause: error},
      );
    }
  }
}

/**
 * Fetches trust boundary data for a given url using an authenticated client.
 * Handles caching checks and potential fallbacks.
 * @param authenticatedClient An authenticated AuthClient instance to make the request.
 * @param url A url for calling the trust boundary api.
 * @param authHeader The header within the auth api.
 * @returns A Promise resolving to TrustBoundaryData or null if fetching fails and no cache is available.
 *  * @throws {Error} If the request fails and there is no cache available.
 */
export async function lookupTrustBoundary(
  client: AuthClient,
  url: string,
  authHeader: string,
): Promise<TrustBoundaryData | null> {
  // Throws error on unrecoverable error with no cache

  if (client.universeDomain !== DEFAULT_UNIVERSE) {
    return null; // Skipping check for non-default universe domain
  }

  const cachedTB = client.trustBoundary;
  if (
    cachedTB &&
    cachedTB.encodedLocations &&
    cachedTB.encodedLocations === NoOpEncodedLocations
  ) {
    return cachedTB; //Returning cached No-Op data.
  }

  try {
    return await _fetchTrustBoundaryData(client, authHeader, url);
  } catch (error) {
    if (cachedTB) {
      return cachedTB; // Falling back to cached data due to error
    }

    throw new Error(
      `TrustBoundary: Error call to API failed and no cache : ${error}`,
    );
  }
}
