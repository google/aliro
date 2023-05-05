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

import com.google.aliro.assertECPointEquals
import com.google.aliro.core.SecureChannelState
import com.google.aliro.hexToBigInteger
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors
import com.google.aliro.messages.ExpeditedStandard
import com.google.aliro.publicKeyFromHex
import com.google.aliro.toAliroIdentifier
import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint

@RunWith(JUnit4::class)
class JvmCommonCryptoTest {
  private val crypto = object : JvmCommonCrypto() {
    override fun generateOrRetrieveKeypair(alias: String): KeyPair {
      throw NotImplementedError()
    }
  }

  @Test
  fun randomBytes() {
    val run1 = crypto.randomBytes(32)
    val run2 = crypto.randomBytes(32)

    assertEquals(32, run1.size)
    assertEquals(32, run2.size)

    assertFalse(run1.contentEquals(run2))
  }

  @Test
  fun decodePublicKey() {
    val expected = ECPoint(
      "ed1c8b8eb7e44c2842db98730717c75cc94c96ab9ae60f079879e756980b4003".hexToBigInteger(),
      "b38fb449203f7237cb9f81077b8ac49c75c8115ed408312222eab61e18feca17".hexToBigInteger()
    )

    assertECPointEquals(
      expected,
      (crypto.decodePublicKey(HexUtil.parseHex(CommonVectors.DEVICE_PUBLIC_KEY)) as ECPublicKey).w
    )
  }

  @Test
  fun `diffieHellmanKeyDerivation outputs the value in the test vectors`() {
    val expected = HexUtil.parseHex(ExpeditedStandard.K_DH)

    val actual = crypto.diffieHellmanKeyDerivation(
      publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      secretKey = keypairFromHex(
        ExpeditedStandard.DEVICE_E_PUBLIC_KEY,
        ExpeditedStandard.DEVICE_E_PRIVATE_KEY
      ).private,
      transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier()
    )

    assertArrayEquals(expected, actual)
  }

  @Test
  fun `verifySignature can verify signatures`() {
    val keypair = crypto.generateEphemeralKeypair()
    val data = DATA.toByteArray()

    val signature = crypto.generateSignature(data, keypair.private)
    val signatureIsVerified = crypto.verifySignature(data, keypair.public, signature)

    assertEquals(JvmCommonCrypto.SIGNATURE_SIZE, signature.size)
    assertTrue(signatureIsVerified)
  }

  @Test
  fun `responseDecryption handles missing keys`() {
    assertThrows(IllegalArgumentException::class.java) {
      val missingKeys = SecureChannelState()

      crypto.responseDecryption(missingKeys, DATA.toByteArray())
    }
  }

  @Test
  fun `responseEncryption handles missing keys`() {
    assertThrows(IllegalArgumentException::class.java) {
      val missingKeys = SecureChannelState()

      crypto.responseEncryption(missingKeys, DATA.toByteArray())
    }
  }

  companion object {
    const val DATA = "'Twas brillig, and the slithy toves"
  }
}