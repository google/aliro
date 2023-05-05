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

/**
 * Aliro APDU commands and their INS values.
 */
object AliroInstructions {
  val AUTH0 = b(0x80)
  val AUTH1 = b(0x81)
  val CONTROL_FLOW = b(0x3C)
  val ENVELOPE = b(0xC3)
  val EXCHANGE = b(0xC9)
  val GET_RESPONSE = b(0xC0)
  val LOAD_CERT = b(0xD1)
  val SELECT = b(0xA4)
}

object ApduClass {
  val INTER_INDUSTRY = b(0x00)
  val PROPRIETARY = b(0x80)
}

@Suppress("NOTHING_TO_INLINE")
internal inline fun b(intValue: Int): Byte = intValue.toByte()
