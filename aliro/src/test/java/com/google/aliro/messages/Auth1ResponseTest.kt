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

import com.google.aliro.core.FixedByteArray
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.publicKeyFromHex
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Auth1ResponseTest {
  private val crypto = JvmCryptoImpl()

  @Test
  fun `Auth1Response toBytes serializes to an ApduResponse`() {
    val ciphertext = HexUtil.parseHex(CIPHERTEXT)
    val expected = ApduResponse(0x42, 0x23, ciphertext)

    assertArrayEquals(expected.serialize(), Auth1Response(0x42, 0x23, ciphertext).toBytes())
  }

  @Test
  fun `Auth1Response toString creates a string that contains the contents`() {
    val response = Auth1Response(0x42, 0x23, HexUtil.parseHex(CIPHERTEXT))

    assertEquals(
      "Auth1Response(sw1=${response.sw1}, sw2=${response.sw2}, ciphertext=$CIPHERTEXT)",
      response.toString()
    )
  }

  @Test
  fun `Auth1Response equals and hashcode function properly`() {
    val response1 = Auth1Response(0x42, 0x23, HexUtil.parseHex(CIPHERTEXT))

    assertEquals(response1, Auth1Response(0x42, 0x23, HexUtil.parseHex(CIPHERTEXT)))
    assertNotEquals(response1, Auth1Response(0x00, 0x23, HexUtil.parseHex(CIPHERTEXT)))
    assertNotEquals(response1, Auth1Response(0x42, 0x00, HexUtil.parseHex(CIPHERTEXT)))
    assertNotEquals(response1, Auth1Response(0x42, 0x23, HexUtil.parseHex("A BAD C0DE")))

    assertEquals(
      response1.hashCode(),
      Auth1Response(0x42, 0x23, HexUtil.parseHex(CIPHERTEXT)).hashCode()
    )
  }

  @Test
  fun `Auth1Response serialization round trips`() {
    val expected = Auth1Response(0x42, 0x23, HexUtil.parseHex(CIPHERTEXT)).toBytes()

    assertArrayEquals(expected, Auth1Response.parse(ApduResponse.parse(expected)).toBytes())
  }

  @Test
  fun `Auth1ResponsePlaintext serialization round trips`() {
    val expected = Auth1ResponsePlaintext(
      FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
      endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
      keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
    )

    assertEquals(expected, Auth1ResponsePlaintext.parse(crypto, expected.toBytes()))
  }

  @Test
  fun `toString includes useful information`() {
    val response = Auth1ResponsePlaintext(
      endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
      endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
      keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
    )

    response.toString().let {
      assertTrue(it.contains("Auth1ResponsePlaintext"))
      assertTrue(it.contains(ENDPOINT_SIGNATURE))
      assertTrue(it.contains(KEY_SLOT))
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val response = Auth1ResponsePlaintext(
      endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
      endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
      keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
    )

    assertEquals(
      response,
      Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
        endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
      )
    )

    assertEquals(
      response.hashCode(),
      Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
        endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
      ).hashCode()
    )

    // endpointSignature
    assertNotEquals(
      response,
      Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(ByteArray(64)),
        endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
      )
    )

    // endpointPk
    assertNotEquals(
      response,
      Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
        endpointPk = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY),
        keySlot = FixedByteArray(HexUtil.parseHex(KEY_SLOT)),
      )
    )

    // keySlot
    assertNotEquals(
      response,
      Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(HexUtil.parseHex(ENDPOINT_SIGNATURE)),
        endpointPk = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        keySlot = FixedByteArray(ByteArray(32)),
      )
    )
  }

  companion object {
    private const val KEY_SLOT = "99887766"
    private const val ENDPOINT_SIGNATURE = "00112233445566778899"
    private const val CIPHERTEXT = "0420CAFE"
  }
}
