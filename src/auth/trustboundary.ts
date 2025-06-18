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
import {GaxiosError, GaxiosOptions} from 'gaxios';
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

/**
 * Fetches trust boundary data using an authenticated client.
 * Handles caching checks and potential fallbacks.
 * @param authenticatedClient An authenticated AuthClient instance to make the request.
 * @returns A Promise resolving to TrustBoundaryData or null for no-op trust boundaries.
 *  * @throws {Error} If the request fails and there is no cache available.
 */
export async function getTrustBoundary(
  client: AuthClient,
): Promise<string | null> {
  if (!client.trustBoundaryEnabled) {
    return null;
  }

  if (client.universeDomain !== DEFAULT_UNIVERSE) {
    return null; // Skipping check for non-default universe domain
  }

  const cachedTB = client.trustBoundary;
  if (cachedTB && cachedTB === NoOpEncodedLocations) {
    return null; //Returning cached No-Op data.
  }

  const trustBoundaryUrl = client.getTrustBoundaryUrl();

  let headers = {};
  if (!client.credentials.access_token && !client.credentials.token_type) {
    throw new Error(
      'TrustBoundary: Error calling lookup endpoint without valid access token',
    );
  }
  headers = new Headers({
    //we can directly pass the access_token as the trust boundaries are always fetched after token refresh
    // authorization:
    //   client.credentials.token_type + ' ' + client.credentials.access_token,
  });

  const opts: GaxiosOptions = {
    ...{
      retry: true,
      retryConfig: {
        httpMethodsToRetry: ['GET', 'PUT', 'POST', 'HEAD', 'OPTIONS', 'DELETE'],
      },
    },
    headers,
    url: trustBoundaryUrl,
  };

  try {
    const {data: trustBoundaryData} =
      // preferred to client.request to avoid unnecessary retries
      await client.transporter.request<TrustBoundaryData>(opts);

    if (
      !trustBoundaryData ||
      typeof trustBoundaryData.encodedLocations !== 'string'
    ) {
      throw new Error(
        'TrustBoundary: Invalid response format from lookup endpoint.',
      );
    }

    // Check for the specific No-Op case and return null.
    if (trustBoundaryData.encodedLocations === NoOpEncodedLocations) {
      return null;
    }

    return trustBoundaryData.encodedLocations;
  } catch (error) {
    if (error instanceof GaxiosError) {
      throw new Error(
        `TrustBoundary: API request to lookup endpoint failed: ${error.message}`,
        {cause: error}, // This preserves the original error for deeper debugging if needed.
      );
    } else if (error instanceof Error) {
      throw new Error(
        `TrustBoundary: Invalid response format from lookup endpoint : ${error.message}`,
        {cause: error}, // This preserves the original error for deeper debugging if needed.
      );
    } else {
      throw new Error(
        'TrustBoundary: Unknown failure while getting trust boundaries:',
        {cause: error}, // This preserves the original error for deeper debugging if needed.
      );
    }
  }
}
