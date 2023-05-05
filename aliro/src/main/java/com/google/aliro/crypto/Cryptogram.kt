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

package com.google.aliro.crypto

import com.google.aliro.core.AliroSerializable
import com.payneteasy.tlv.HexUtil

class Cryptogram(val byteArray: ByteArray) : AliroSerializable {
  override fun toBytes(): ByteArray {
    return byteArray.clone()
  }

  override fun toString() = "Cryptogram(${HexUtil.toHexString(byteArray)})"

  override fun hashCode() = byteArray.contentHashCode()

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Cryptogram) return false

    return byteArray.contentEquals(other.byteArray)
  }
}
