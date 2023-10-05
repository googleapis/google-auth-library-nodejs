// Copyright 2023 Google LLC
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

export interface LRUCacheOptions {
  /**
   * The maximum number of items to cache.
   */
  capacity: number;
  /**
   * An optional max age for items in milliseconds.
   */
  maxAge?: number;
}

/**
 * A simple LRU cache utility.
 * Not meant for external usage.
 *
 * @experimental
 * @internal
 */
export class LRUCache<T> {
  readonly capacity: number;

  /**
   * Maps are in order. Thus, the older item is the first item.
   *
   * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map}
   */
  #cache = new Map<string, {lastAccessed: number; value: T}>();
  maxAge?: number;

  constructor(options: LRUCacheOptions) {
    this.capacity = options.capacity;
    this.maxAge = options.maxAge;
  }

  /**
   * Moves the key to the end of the cache.
   *
   * @param key the key to move
   * @param value the value of the key
   */
  #moveToEnd(key: string, value: T) {
    this.#cache.delete(key);
    this.#cache.set(key, {
      value,
      lastAccessed: Date.now(),
    });
  }

  /**
   * Add an item to the cache.
   *
   * @param key the key to upsert
   * @param value the value of the key
   */
  set(key: string, value: T) {
    this.#moveToEnd(key, value);
    this.#evict();
  }

  /**
   * Get an item from the cache.
   *
   * @param key the key to retrieve
   */
  get(key: string): T | undefined {
    const item = this.#cache.get(key);
    if (!item) return;

    this.#moveToEnd(key, item.value);
    this.#evict();

    return item.value;
  }

  /**
   * Maintain the cache based on capacity and TTL.
   */
  #evict() {
    const cutoffDate = this.maxAge ? Date.now() - this.maxAge : 0;

    /**
     * Because we know Maps are in order, this item is both the
     * last item in the list (capacity) and oldest (maxAge).
     */
    let oldestItem = this.#cache.entries().next();

    while (
      !oldestItem.done &&
      (this.#cache.size > this.capacity || // too many
        oldestItem.value[1].lastAccessed < cutoffDate) // too old
    ) {
      this.#cache.delete(oldestItem.value[0]);
      oldestItem = this.#cache.entries().next();
    }
  }
}
