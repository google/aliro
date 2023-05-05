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
import org.junit.Assert
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class FixedByteArrayTest {
  @Test
  fun `FixedByteArrays have a fixed-size`() {
    val size = 25
    val fba = FixedByteArray(size)

    assertEquals(size, fba.bytes.size)
  }

  @Test
  fun `FixedByteArrays can access the underlying byte array`() {
    val size = 25
    val fba = FixedByteArray(size)
    fba.bytes[21] = 42

    assertEquals(42.toByte(), fba[21])

    fba[23] = 123

    assertEquals(123.toByte(), fba.bytes[23])
  }

  @Test
  fun `FixedByteArrays have working equals and hashcode functions`() {
    val size = 5
    val fba1 = FixedByteArray(size)
    val fba2 = FixedByteArray(size)

    fba1[3] = 123
    fba2[3] = 123

    assertEquals(fba1, fba2)
    assertEquals(fba1.hashCode(), fba2.hashCode())

    fba2[0] = 42

    assertNotEquals(fba1, fba2)
    assertNotEquals(fba1.hashCode(), fba2.hashCode())
  }

  @Test
  fun `initializing a FixedByteArray from an array works as expected`() {
    val ba = HexUtil.parseHex("001122334455")

    val fba = FixedByteArray(ba)

    Assert.assertArrayEquals(ba, fba.bytes)
  }

  @Test
  fun `initializing a FixedByteArray from a size and array does size checking`() {
    val ba = HexUtil.parseHex("001122334455")

    // throws no errors
    val fba = FixedByteArray(ba.size, ba)
    assertEquals(ba.size, fba.bytes.size)

    assertThrows(IllegalArgumentException::class.java) {
      FixedByteArray(ba.size - 1, ba)
    }
  }

  @Test
  fun `hex output works properly`() {
    val hexString = "001122334455AABBCCDDEEFF"
    assertEquals(hexString, FixedByteArray(HexUtil.parseHex(hexString)).toHexString())
  }
}
