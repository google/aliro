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

import com.payneteasy.tlv.HexUtil

/**
 * A fixed-size byte array.
 *
 * This is largely a convenience wrapper of [ByteArray] which performs size checking and provides
 * an [equals], [hashCode], and [toString] implementation.
 */
class FixedByteArray internal constructor(size: Int, val bytes: ByteArray) {
  /**
   * Construct an empty [FixedByteArray] of the given [size] (bytes).
   */
  constructor(size: Int) : this(size, ByteArray(size))

  /**
   * Construct a [FixedByteArray] from [bytes]. This makes a copy of array.
   */
  constructor(bytes: ByteArray) : this(bytes.size, bytes.clone())

  init {
    require(bytes.size == size) { "FixedByteArray size must be $size, but was ${bytes.size}" }
  }

  operator fun get(i: Int) = bytes[i]
  operator fun set(i: Int, b: Byte) {
    bytes[i] = b
  }

  override fun hashCode() = bytes.contentHashCode()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is FixedByteArray) return false

    return bytes.contentEquals(other.bytes)
  }

  override fun toString(): String {
    return "<${HexUtil.toHexString(bytes)}>"
  }

  fun toHexString(): String {
    return HexUtil.toHexString(bytes)
  }
}