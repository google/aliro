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

package com.google.aliro.messages

import com.google.aliro.core.toHex
import com.google.aliro.responseFromHex
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil.parseHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelectResponseTest {
  @Test
  fun `test SELECT response serializer`() {
    val response = SelectResponse(
      selectedAid = parseHex("F0006B7369000002"),
      supportedVersions = parseHex("01000007"),
      type = parseHex("0000"),
    )
    val expected =
      parseHex("6F 16 84 08 F0006B7369000002 A5 0A 80 02 0000 81 04 01000007 9000")

    assertArrayEquals(expected, response.toBytes())

    assertEquals(response, SelectResponse.parse(ApduResponse.parse(expected)))
  }

  @Test
  fun `SelectResponse can round trip`() {
    val expected = SelectResponse(
      selectedAid = parseHex("F0006B7369000002"),
      supportedVersions = parseHex("01000007"),
      type = parseHex("0000"),
      capabilities = parseHex(FAKE_CAPABILITIES),
    )

    assertEquals(expected, SelectResponse.parse(ApduResponse.parse(expected.toBytes())))
  }

  @Test
  fun `test SELECT response with test vectors`() {
    val expected = SelectResponse(
      selectedAid = parseHex(CommonVectors.AID),
      supportedVersions = parseHex("0100"),
      type = parseHex(TYPE),
    )
    assertEquals(expected, SelectResponse.parse(responseFromHex(CommonVectors.SELECT_RESPONSE)))
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val response1 = SelectResponse(
      selectedAid = SelectCommand.AID,
      supportedVersions = parseHex(SUPPORTED_VERSIONS),
      type = parseHex(TYPE),
      capabilities = parseHex(FAKE_CAPABILITIES),
    )

    assertEquals(
      response1, SelectResponse(
        selectedAid = SelectCommand.AID,
        supportedVersions = parseHex(SUPPORTED_VERSIONS),
        type = parseHex(TYPE),
        capabilities = parseHex(FAKE_CAPABILITIES),
      )
    )

    assertEquals(
      response1.hashCode(), SelectResponse(
        selectedAid = SelectCommand.AID,
        supportedVersions = parseHex(SUPPORTED_VERSIONS),
        type = parseHex(TYPE),
        capabilities = parseHex(FAKE_CAPABILITIES),
      ).hashCode()
    )

    assertNotEquals(
      response1,
      SelectResponse(
        selectedAid = byteArrayOf(0x00),
        supportedVersions = parseHex(SUPPORTED_VERSIONS),
        type = parseHex(TYPE),
        capabilities = parseHex(FAKE_CAPABILITIES),
      )
    )

    assertNotEquals(
      response1,
      SelectResponse(
        selectedAid = SelectCommand.AID,
        supportedVersions = parseHex("0007"),
        type = parseHex(TYPE),
        capabilities = parseHex(FAKE_CAPABILITIES),
      )
    )

    assertNotEquals(
      response1, SelectResponse(
        selectedAid = SelectCommand.AID,
        supportedVersions = parseHex(SUPPORTED_VERSIONS),
        type = parseHex("0001"),
        capabilities = parseHex(FAKE_CAPABILITIES),
      )
    )

    assertNotEquals(
      response1, SelectResponse(
        selectedAid = SelectCommand.AID,
        supportedVersions = parseHex(SUPPORTED_VERSIONS),
        type = parseHex(TYPE),
        capabilities = null,
      )
    )
  }

  @Test
  fun `toString contains useful information`() {
    val response = SelectResponse(
      selectedAid = SelectCommand.AID,
      supportedVersions = parseHex(SUPPORTED_VERSIONS),
      type = parseHex(TYPE),
      capabilities = parseHex(FAKE_CAPABILITIES),
    )

    response.toString().let {
      assertTrue(it.contains("SelectResponse"))
      assertTrue(it.contains(SelectCommand.AID.toHex()))
      assertTrue(it.contains(SUPPORTED_VERSIONS))
      assertTrue(it.contains("type=$TYPE"))
      assertTrue(it.contains("capabilities=$FAKE_CAPABILITIES"))
    }
  }

  companion object {
    const val FAKE_CAPABILITIES = "001122334455"
    const val SUPPORTED_VERSIONS = "01000007"
    const val TYPE = "0000"
  }
}
