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

package com.google.aliro

import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class VersionsTest {
  @Test
  fun testToByteArray() {
    val expected = byteArrayOf(0x01, 0x00)
    assertArrayEquals(expected, VersionsImpl.toByteArray(VersionsImpl.PROTOCOL_VERSION_0100))
  }

  @Test
  fun testToByteArrayHighBytes() {
    assertArrayEquals(byteArrayOf(0xfe.toByte(), 0xed.toByte()), VersionsImpl.toByteArray(0xfeed))
  }

  @Test
  fun `highestSupportedVersion functions correctly`() {
    assertEquals(
      VersionsImpl.PROTOCOL_VERSION_0100,
      VersionsImpl.highestSupportedVersion(HexUtil.parseHex("0100"))
    )
    // This is ordered backwards
    assertEquals(
      VersionsImpl.PROTOCOL_VERSION_0100,
      VersionsImpl.highestSupportedVersion(HexUtil.parseHex("0000 0100 1234"))
    )
    assertEquals(
      VersionsImpl.PROTOCOL_VERSION_0100,
      VersionsImpl.highestSupportedVersion(HexUtil.parseHex("1234 0100 0007"))
    )
    assertEquals(
      VersionsImpl.PROTOCOL_VERSION_0007,
      VersionsImpl.highestSupportedVersion(HexUtil.parseHex("1234 0101 0007"))
    )
    assertEquals(
      VersionsImpl.PROTOCOL_VERSION_0007,
      VersionsImpl.highestSupportedVersion(HexUtil.parseHex("1234 0007"))
    )

    assertNull(VersionsImpl.highestSupportedVersion(HexUtil.parseHex("")))
    assertNull(VersionsImpl.highestSupportedVersion(HexUtil.parseHex("0000")))
    assertNull(VersionsImpl.highestSupportedVersion(HexUtil.parseHex("0002")))
    assertNull(VersionsImpl.highestSupportedVersion(HexUtil.parseHex("1234 0202 0002")))
  }

  @Test
  fun `isVersionSupported functions properly`() {
    assertTrue(VersionsImpl.isVersionSupported(VersionsImpl.PROTOCOL_VERSION_0007))
    assertTrue(VersionsImpl.isVersionSupported(VersionsImpl.PROTOCOL_VERSION_0100))

    assertFalse(VersionsImpl.isVersionSupported(0))
    assertFalse(VersionsImpl.isVersionSupported(-1))
    assertFalse(VersionsImpl.isVersionSupported(1))
  }
}