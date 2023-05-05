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

package com.google.aliro.reader

import com.google.aliro.core.FixedByteArray
import java.security.PublicKey
import java.util.Objects

class KnownUserDevice(val publicKey: PublicKey, val kPersistent: FixedByteArray) {
  override fun toString() = "KnownUserDevice(publicKey=$publicKey, kPersistent=<redacted>)"

  override fun hashCode() = Objects.hash(publicKey, kPersistent)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is KnownUserDevice) return false

    if (publicKey != other.publicKey) return false
    return kPersistent == other.kPersistent
  }
}
