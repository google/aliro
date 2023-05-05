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

import com.google.aliro.messages.ExpeditedFast
import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class CryptogramTest {
  @Test
  fun `equals and hashcode function properly`() {
    val expected = Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM))

    assertEquals(expected, Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM)))
    assertNotEquals(expected, Cryptogram(HexUtil.parseHex(ExpeditedFast.BLE_SK)))

    assertEquals(
      expected.hashCode(),
      Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM)).hashCode()
    )
  }
}