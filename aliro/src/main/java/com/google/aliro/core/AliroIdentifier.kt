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

package com.google.aliro.core

import com.google.aliro.crypto.AliroCrypto
import java.util.Objects

class AliroIdentifier internal constructor(val identifier: FixedByteArray) : AliroSerializable {
  constructor(byteArray: ByteArray) : this(FixedByteArray(IDENTIFIER_SIZE, byteArray))

  override fun toBytes() = identifier.bytes.clone()

  override fun toString() = "AliroId($identifier)"

  override fun hashCode() = Objects.hash(identifier)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AliroIdentifier) return false

    return identifier == other.identifier
  }

  companion object {
    private const val IDENTIFIER_SIZE = 16

    @JvmStatic
    fun randomIdentifier(crypto: AliroCrypto) = AliroIdentifier(crypto.randomBytes(IDENTIFIER_SIZE))
  }
}