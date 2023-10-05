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

/**
 * A utility for converting snake_case to camelCase
 *
 * For, for example `my_snake_string` becomes `mySnakeString`.
 */
export type SnakeToCamel<S> = S extends `${infer FirstWord}_${infer Remainder}`
  ? `${FirstWord}${Capitalize<SnakeToCamel<Remainder>>}`
  : S;

/**
 * A utility for converting an type's keys from snake_case
 * to camelCase, if the keys are strings.
 *
 * For example:
 *
 * ```ts
 * {
 *   my_snake_string: boolean;
 *   myCamelString: string;
 * }
 * ```
 *
 * becomes:
 *
 * ```ts
 * {
 *   mySnakeString: boolean;
 *   myCamelString: string;
 * }
 * ```
 *
 * @remarks
 *
 * The generated documentation for the camelCase'd properties won't be available
 * until {@link https://github.com/microsoft/TypeScript/issues/50715} has been
 * resolved.
 */
export type SnakeToCamelObject<T> = {
  [K in keyof T as SnakeToCamel<K>]: T[K];
};

/**
 * A utility for adding camelCase versions of a type's snake_case keys, if the
 * keys are strings, preserving any existing keys.
 *
 * For example:
 *
 * ```ts
 * {
 *   my_snake_string: boolean;
 *   myCamelString: string;
 * }
 * ```
 *
 * becomes:
 *
 * ```ts
 * {
 *   my_snake_string: boolean;
 *   mySnakeString: boolean;
 *   myCamelString: string;
 * }
 * ```
 * @remarks
 *
 * The generated documentation for the camelCase'd properties won't be available
 * until {@link https://github.com/microsoft/TypeScript/issues/50715} has been
 * resolved.
 */
export type OriginalAndCamel<T> = T & SnakeToCamelObject<T>;

/**
 * Returns the camel case of a provided string.
 *
 * @remarks
 *
 * Match any `_` and not `_` pair, then return the uppercase of the not `_`
 * character
 *
 * @param str the string to convert
 * @returns
 */
export function snakeToCamel<T extends string>(str: T): SnakeToCamel<T> {
  return str.replace(/([_][^_])/g, match =>
    match.slice(1).toUpperCase()
  ) as SnakeToCamel<T>;
}

/**
 * Returns the value of `obj[key]` or `obj[camelCaseKey]`, with a preference
 * for original, non-camelCase key.
 *
 * @param obj object to lookup a value in
 * @param key an index of object, preferably snake_case
 * @returns the value `obj[key || snakeKey]`, if available
 */
export function getOriginalOrCamel<
  T extends {},
  K extends keyof OriginalAndCamel<T> & string,
>(obj: T, key: K): OriginalAndCamel<T>[K] {
  const o = obj as OriginalAndCamel<T>;
  return o[key] ?? o[snakeToCamel(key) as K];
}
