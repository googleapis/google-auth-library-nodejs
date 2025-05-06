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

import { AuthClient } from './authclient';
import { GaxiosError, GaxiosOptions, GaxiosResponse } from 'gaxios';


// NoOpEncodedLocations is a special value indicating that no trust boundary is enforced.
const NoOpEncodedLocations = "0x0";
// universeDomainDefault is the default domain for Google Cloud Universe.
const universeDomainDefault = "googleapis.com";
// ServiceAccountAllowedLocationsEndpoint is the URL for fetching allowed locations for a given service account email.
// The '%s' will be replaced with the URL-encoded service account email.
const ServiceAccountAllowedLocationsEndpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s/allowedLocations";


// --- Interfaces ---

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
 * This interface allows different authentication types to pass info
 * Service Account -> email
 * Workload Identity Pool -> project_id, pool_id
 * Workforce Pool -> pool_id
 */
export interface TrustBoundaryDescriptor {
  project_id?: string,
  pool_id?: string,
  email?: string
}
  
export interface TrustBoundaryProvider {
  fetchTrustBoundary: (tbDescriptor: TrustBoundaryDescriptor) => Promise<TrustBoundaryData|null>;
}

// --- TrustBoundary Class ---

/**
 * Represents trust boundary information, holding allowed locations.
 */
export class TrustBoundary {
    // The readable text format of the allowed trust boundary locations
    readonly locations?: string[];
    // The encoded text format of allowed trust boundary locations
    readonly encodedLocations: string;

    /**
     * Creates an instance of TrustBoundary.
     * @param locations Optional array of allowed location strings.
     * @param encodedLocations The encoded location string. Defaults to NoOpEncodedLocations.
     */
    constructor (
        locations?: string[],
        encodedLocations : string = NoOpEncodedLocations
    ) {
        // Store a copy of the locations array if provided
        this.locations = locations ? [...locations] : undefined;
        this.encodedLocations = encodedLocations;
    }

    /**
     * Gets a copy of the allowed locations array.
     * @returns A copy of the locations array, or undefined if not set.
     */
    getLocations(): string[] | undefined {
        return this.locations ? [...this.locations] : undefined;
    }

    /**
     * Gets the encoded locations string.
     * @returns The encoded locations string.
     */
    getEncodedLocations(): string {
        return this.encodedLocations ? this.encodedLocations : "";
    }

    /**
     * Checks if the trust boundary is effectively empty or represents no restrictions.
     * @returns True if no encoded locations are set or if it's the No-Op value, false otherwise.
     */
    isNoOpOrEmpty(): boolean {
        return !this.encodedLocations || this.encodedLocations === NoOpEncodedLocations;
    }
}



// --- Internal Helper Function ---

/**
 * Internal helper function to fetch trust boundary data from a specific URL.
 * Corresponds to Go's fetchTrustBoundaryData.
 *
 * @param authenticatedClient An authenticated AuthClient instance.
 * @param url The specific URL to fetch data from.
 * @returns A Promise resolving to a new TrustBoundary instance.
 * @throws {Error} If the request fails or the response is invalid.
 * @internal
 */
async function _fetchTrustBoundaryData(
  authenticatedClient: AuthClient,
  url: string,
): Promise<TrustBoundaryData> { // Throws on error instead of returning null

  if (!url) {
      throw new Error("TrustBoundary: URL cannot be empty for fetching data.");
  }

  const requestOptions: GaxiosOptions = {
    method: 'GET',
    url: url,
    timeout: 5000, // todo: make this configurable 5 seconds
  };

  console.log(`TrustBoundary: Fetching data from ${url}`);
  try {
    const response: GaxiosResponse<TrustBoundaryData> = await authenticatedClient.transporter.request<TrustBoundaryData>(requestOptions)
    console.log("Response from lookup endpoint "+ response)
    // const response: GaxiosResponse<AllowedLocationsResponse> = await authenticatedClient.request<AllowedLocationsResponse>(requestOptions);
    if (response.status === 200 && response.data) {
      const trustBoundaryData = response.data;

      // Basic validation of the response structure
      if (typeof trustBoundaryData.encodedLocations !== 'string') {
         throw new Error('TrustBoundary: Invalid response format - missing or invalid encodedLocations');
      }

      console.log('TrustBoundary: Successfully fetched data.');
      return trustBoundaryData

    } else {
      // Handle unexpected non-error statuses (though gaxios usually throws for >=400)
      throw new Error(`TrustBoundary: Request failed with status ${response.status}`);
    }
  } catch (error) {
    console.error(`TrustBoundary: Failed request to ${url}.`);
    if (error instanceof GaxiosError) {
      console.error(`Status: ${error.response?.status}, Message: ${error.message}, Body:`, error.response?.data);
      // Re-throw a more specific error or the original GaxiosError
      throw new Error(`TrustBoundary: API request failed with status ${error.response?.status}: ${error.message}`);
    } else if (error instanceof Error) {
      // Re-throw the original error or wrap it
      throw new Error(`TrustBoundary: Network or unexpected error: ${error.message}`);
    } else {
      // Handle unknown error types
      throw new Error(`TrustBoundary: An unknown error occurred during fetch: ${error}`);
    }
  }
}


// --- Exported Lookup Function ---

/**
 * Fetches trust boundary data for a given service account email using an authenticated client.
 * Handles caching checks and potential fallbacks.
 * Corresponds to Go's LookupServiceAccountTrustBoundary.
 *
 * @param authenticatedClient An authenticated AuthClient instance to make the request.
 * @param serviceAccountEmail The email of the service account to look up.
 * @param cachedData Optional previously fetched data to check for no-op or use as fallback on error.
 * @returns A Promise resolving to TrustBoundaryData or null if fetching fails and no cache is available.
 */
export async function lookupServiceAccountTrustBoundary(
  authenticatedClient: AuthClient,
  serviceAccountEmail?: string,
  cachedData?: TrustBoundaryData|null
): Promise<TrustBoundaryData | null> { // Returns null on unrecoverable error with no cache

  // --- Input Validation ---
  if (!authenticatedClient) {
    console.error('TrustBoundaryLookup: Authenticated client is required.');
    return cachedData ?? null; // Use cache if available, else null
  }
  if (!serviceAccountEmail) {
    console.error('TrustBoundaryLookup: Service account email cannot be empty.');
    return cachedData ?? null;
  }

  // --- Check Universe Domain ---
  const universeDomain = authenticatedClient.universeDomain || universeDomainDefault;
  if (universeDomain !== universeDomainDefault) {
    console.log(`TrustBoundaryLookup: Skipping check for non-default universe domain: ${universeDomain}`);
    return new TrustBoundary(undefined, NoOpEncodedLocations); // Return No-Op
  }

  // --- Check Cached Data for No-Op ---
  if (cachedData && cachedData.encodedLocations && cachedData.encodedLocations === NoOpEncodedLocations) {
    console.log('TrustBoundaryLookup: Returning cached No-Op data.');
    return cachedData;
  }

  // --- Prepare URL and Fetch --- 
  const url = ServiceAccountAllowedLocationsEndpoint.replace('%s', encodeURIComponent(serviceAccountEmail));
 
  try {
    // Call the internal fetch function
    return await _fetchTrustBoundaryData(authenticatedClient, url);
  } catch (error) {
    // --- Handle Errors and Fallback ---
    console.error('TrustBoundaryLookup: Failed to fetch trust boundary data.');
    if (error instanceof Error) {
      console.error(error.message); // Log the specific error message
    } else {
      console.error('An unknown error occurred during lookup.', error);
    }

    // Fallback to cached data if available on error
    if (cachedData) {
      console.warn('TrustBoundaryLookup: Falling back to cached data due to error.');
      return cachedData;
    }

    // If no cache, return null to indicate failure without fallback
    return null;
  }
}