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
 * Retrieve the byte at the given index.
 */
internal fun Int.byteAtIndex(index: Int): Byte =
  (this.shr(Byte.SIZE_BITS * index) and 0xff).toByte()

internal fun Int.to2ByteArray() =
  byteArrayOf(b(this.shr(8) and 0xff), b(this and 0xff))

internal fun ByteArray.toHex(): String = HexUtil.toHexString(this)