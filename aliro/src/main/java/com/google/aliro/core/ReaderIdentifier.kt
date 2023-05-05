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

import java.io.ByteArrayOutputStream
import java.util.Objects

class ReaderIdentifier(
  val groupIdentifier: AliroIdentifier,
  val groupSubIdentifier: AliroIdentifier,
) : AliroSerializable {
  constructor(byteArray: ByteArray) : this(
    AliroIdentifier(byteArray.sliceArray(0 until 16)),
    AliroIdentifier(byteArray.sliceArray(16 until 32))
  )

  override fun toString() = "ReaderIdentifier(${
    groupIdentifier.identifier.toHexString().lowercase()
  }-${groupSubIdentifier.identifier.toHexString().lowercase()})"

  override fun hashCode() = Objects.hash(groupIdentifier, groupSubIdentifier)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ReaderIdentifier) return false

    if (groupIdentifier != other.groupIdentifier) return false
    return groupSubIdentifier == other.groupSubIdentifier
  }

  override fun toBytes(): ByteArray {
    val baos = ByteArrayOutputStream(32)

    baos.write(groupIdentifier.toBytes())
    baos.write(groupSubIdentifier.toBytes())

    return baos.toByteArray()
  }
}
