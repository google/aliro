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

import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.publicKeyFromHex
import com.google.aliro.reader.AliroReaderContext
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class Auth0ResponseTest {
  private val mockContext = mockk<AliroReaderContext>()
  private val crypto = mockk<JvmCryptoImpl>()

  @Before
  fun init() {
    every { mockContext.crypto } returns crypto

    every { crypto.decodePublicKey(any()) } answers { callOriginal() }
  }

  @Test
  fun `test AUTH0 response round-trip`() {
    val expected = HexUtil.parseHex(AUTH0_RESPONSE_SPEC)
    val response = Auth0Response.parse(mockContext, ApduResponse.parse(expected))

    assertArrayEquals(expected, response.toBytes())
  }

  @Test
  fun `endpoint epk and cryptogram match expected values`() {
    val response = Auth0Response.parse(
      aliroContext = mockContext,
      apduResponse = ApduResponse.parse(HexUtil.parseHex(AUTH0_RESPONSE_SPEC))
    )

    assertArrayEquals(HexUtil.parseHex(ENDPOINT_EPK), response.endpointEPk.encodeBasic())
    assertArrayEquals(HexUtil.parseHex(CRYPTOGRAM), response.cryptogram?.byteArray)
  }

  @Test
  fun `toString outputs a useful string`() {
    val response = Auth0Response.parse(
      mockContext,
      ApduResponse.parse(HexUtil.parseHex(AUTH0_RESPONSE_SPEC))
    )

    response.toString().let {
      assertTrue(it.contains("Auth0Response"))
      assertTrue(it.contains(CRYPTOGRAM))
      assertTrue(it.contains("endpointEPk="))
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val response =
      Auth0Response(
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        cryptogram = Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM))
      )

    assertEquals(
      response, Auth0Response(
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        cryptogram = Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM))
      )
    )

    assertEquals(
      response.hashCode(), Auth0Response(
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        cryptogram = Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM))
      ).hashCode()
    )

    // endpointEPk
    assertNotEquals(
      response, Auth0Response(
        endpointEPk = publicKeyFromHex(ExpeditedFast.READER_E_PUBLIC_KEY),
        cryptogram = Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM))
      )
    )

    // cryptogram
    assertNotEquals(
      response, Auth0Response(
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        cryptogram = Cryptogram(ByteArray(16))
      )
    )
  }

  companion object {
    const val ENDPOINT_EPK = """
0443D605526999F032E08F314F22EBCE051D1DAE53DC71F1C4D614B0337BB17F20
3F95D4C06AB8966D2B9A0D3C4BC446DB9343EBF27F9EF811F242A37118AD4F10
    """
    const val CRYPTOGRAM = "C90153556AFD43F3594D4CA380E909D3"
    const val AUTH0_RESPONSE_SPEC = """
86410443D605526999F032E08F314F22EBCE051D1DAE53DC71F1C4D614B0337B
B17F203F95D4C06AB8966D2B9A0D3C4BC446DB9343EBF27F9EF811F242A37118
AD4F109D10C90153556AFD43F3594D4CA380E909D39000
"""
  }
}