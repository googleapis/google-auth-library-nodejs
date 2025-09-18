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

/**
 * value indicating no trust boundaries enforced
 **/
export const NoOpEncodedLocations = '0x0';

// googleapis.com
export const SERVICE_ACCOUNT_LOOKUP_ENDPOINT =
  'https://iamcredentials.{universe_domain}/v1/projects/-/serviceAccounts/{service_account_email}/allowedLocations';

export const WORKLOAD_LOOKUP_ENDPOINT =
  'https://iamcredentials.{universe_domain}/v1/projects/{project_id}/locations/global/workloadIdentityPools/{pool_id}/allowedLocations';

export const WORKFORCE_LOOKUP_ENDPOINT =
  'https://iamcredentials.{universe_domain}/v1/locations/global/workforcePools/{pool_id}/allowedLocations';

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

export function isTrustBoundaryEnabled() {
  const tbEnabled = process.env['GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED'];
  if (tbEnabled === undefined || tbEnabled === null) {
    return false;
  }
  const lowercasedTbEnabled = tbEnabled.toLowerCase();
  if (lowercasedTbEnabled === 'true' || tbEnabled === '1') {
    return true;
  }
  if (lowercasedTbEnabled === 'false' || tbEnabled === '0') {
    return false;
  }
  throw new Error(
    `Invalid value for GOOGLE_AUTH_TRUST_BOUNDARY_ENABLED environment variable: "${tbEnabled}". Supported values are 'true', '1', 'false', or '0'.`,
  );
}
