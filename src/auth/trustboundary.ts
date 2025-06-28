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
import {GaxiosOptions} from 'gaxios';
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
 * Fetches trust boundary data for an authenticated client.
 * Handles caching checks and potential fallbacks.
 * @param authenticatedClient An authenticated AuthClient instance to make the request.
 * @returns A Promise resolving to TrustBoundaryData or empty-string for no-op trust boundaries.
 * @throws {Error} If the request fails and there is no cache available.
 */
export async function getTrustBoundary(
  client: AuthClient,
): Promise<TrustBoundaryData | null> {
  if (!client.trustBoundaryEnabled) {
    return null;
  }

  if (client.universeDomain !== DEFAULT_UNIVERSE) {
    return null; // Skipping check for non-default universe domain
  }

  const cachedTB = client.trustBoundary;
  if (cachedTB && cachedTB.encodedLocations === NoOpEncodedLocations) {
    return cachedTB; //Returning cached No-Op data.
  }

  const trustBoundaryUrl = client.getTrustBoundaryUrl();
  if (!trustBoundaryUrl) {
    throw new Error(
      'TrustBoundary: GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED env variable set for invalid client type',
    );
  }

  if (!client.credentials.access_token) {
    throw new Error(
      'TrustBoundary: Error calling lookup endpoint without valid access token',
    );
  }
  const headers = new Headers({
    //we can directly pass the access_token as the trust boundaries are always fetched after token refresh
    authorization: 'Bearer ' + client.credentials.access_token,
  });

  const opts: GaxiosOptions = {
    ...{
      retry: true,
      retryConfig: {
        httpMethodsToRetry: ['GET'],
      },
    },
    headers,
    url: trustBoundaryUrl,
  };

  try {
    const {data: trustBoundaryData} =
      // preferred to client.request to avoid unnecessary retries
      await client.transporter.request<TrustBoundaryData>(opts);

    if (!trustBoundaryData.encodedLocations) {
      throw new Error(
        'TrustBoundary: Malformed response from lookup endpoint.',
      );
    }

    return trustBoundaryData;
  } catch (error) {
    if (client.trustBoundary) {
      return client.trustBoundary; // return cached tb if call to lookup fails
    }
    throw new Error('TrustBoundary: Failure while getting trust boundaries:', {
      cause: error,
    });
  }
}

export function isTrustBoundaryEnabled() {
  const tbEnabled = process.env['GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED'] || null;
  const truthyValues = new Set(['1', 't', 'T', 'TRUE', 'true', 'True']);
  const falsyValues = new Set(['0', 'f', 'F', 'FALSE', 'false', 'False']);
  if (
    tbEnabled === null ||
    tbEnabled === undefined ||
    falsyValues.has(tbEnabled)
  ) {
    return false;
  }
  if (truthyValues.has(tbEnabled)) {
    return true;
  }
  throw new Error(
    `Invalid syntax for the GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED env variable: "${tbEnabled}" is not a valid boolean representation`,
  );
}
