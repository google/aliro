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

import org.junit.Assert.assertEquals
import org.junit.Test

class ByteToolsKtTest {
  @Test
  fun `toHex outputs hex appropriately`() {
    assertEquals("", byteArrayOf().toHex())
    assertEquals("00", byteArrayOf(0x00).toHex())
    assertEquals("CAFE", byteArrayOf(b(0xca), b(0xfe)).toHex())
  }
}