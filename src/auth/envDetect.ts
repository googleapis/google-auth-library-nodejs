/**
 * Copyright 2018 Google LLC. All Rights Reserved.
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

import * as gcpMetadata from 'gcp-metadata';

export enum GCPEnv {
  APP_ENGINE = 'APP_ENGINE',
  KUBERNETES_ENGINE = 'KUBERNETES_ENGINE',
  CLOUD_FUNCTIONS = 'CLOUD_FUNCTIONS',
  COMPUTE_ENGINE = 'COMPUTE_ENGINE',
  NONE = 'NONE',
}

let env: GCPEnv | undefined;

export function clear() {
  env = undefined;
}

export async function getEnv() {
  if (!env) {
    if (isAppEngine()) {
      env = GCPEnv.APP_ENGINE;
    } else if (isCloudFunction()) {
      env = GCPEnv.CLOUD_FUNCTIONS;
    } else if (await isComputeEngine()) {
      if (await isKubernetesEngine()) {
        env = GCPEnv.KUBERNETES_ENGINE;
      } else {
        env = GCPEnv.COMPUTE_ENGINE;
      }
    } else {
      env = GCPEnv.NONE;
    }
  }
  return env;
}

function isAppEngine() {
  return !!(process.env.GAE_SERVICE || process.env.GAE_MODULE_NAME);
}

function isCloudFunction() {
  return !!(process.env.FUNCTION_NAME || process.env.FUNCTION_TARGET);
}

async function isKubernetesEngine() {
  try {
    await gcpMetadata.instance('attributes/cluster-name');
    return true;
  } catch (e) {
    return false;
  }
}

async function isComputeEngine() {
  return gcpMetadata.isAvailable();
}
