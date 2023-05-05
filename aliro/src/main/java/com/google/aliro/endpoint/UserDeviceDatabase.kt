/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.aliro.endpoint

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier

/**
 * Aa database that stores [Endpoint]s.
 */
interface UserDeviceDatabase {
  /**
   * Locate the [Endpoint](s) that contains the given [readerGroupIdentifier].
   * If none are found, returns an empty set.
   */
  fun findEndpoints(readerGroupIdentifier: AliroIdentifier): Set<Endpoint>

  /**
   * Return a randomly-generated dummy endpoint. This should be stored in the database.
   */
  fun dummyEndpoint(): Endpoint

  fun findReaderGroup(readerGroupIdentifier: AliroIdentifier): KnownReaderGroup?

  fun storeReaderGroup(endpoint: Endpoint, knownReaderGroup: KnownReaderGroup)

  fun dummyReaderGroup(): KnownReaderGroup

  fun findPersistentKey(readerIdentifier: ReaderIdentifier): FixedByteArray?

  fun storePersistentKey(readerIdentifier: ReaderIdentifier, kPersistent: FixedByteArray)

  fun dummyPersistentKey(): FixedByteArray

  fun debug(): String
}