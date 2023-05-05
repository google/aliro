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
import java.security.PublicKey
import java.util.Objects

class KnownReaderGroup(
  val readerGroupIdentifier: AliroIdentifier,
  val readerPublicKey: PublicKey,
) {
  override fun toString() =
    "KnownReaderGroup(readerID=$readerGroupIdentifier, publicKey=$readerPublicKey)"

  override fun hashCode() = Objects.hash(readerGroupIdentifier, readerPublicKey)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is KnownReaderGroup) return false

    if (readerGroupIdentifier != other.readerGroupIdentifier) return false

    return readerPublicKey == other.readerPublicKey
  }

  companion object {
    const val K_PERSISTENT_SIZE = 32
  }
}