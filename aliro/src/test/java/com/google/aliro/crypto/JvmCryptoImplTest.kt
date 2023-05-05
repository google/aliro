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

import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

@RunWith(JUnit4::class)
class JvmCryptoImplTest {

  private val crypto = JvmCryptoImpl()

  @Test
  fun `generateOrRetrieveKeypair does just that`() {
    val keypair = crypto.generateOrRetrieveKeypair("foo")

    assertTrue(keypair.public is ECPublicKey)
    assertTrue(keypair.private is ECPrivateKey)

    val data = JvmCommonCryptoTest.DATA.toByteArray()
    val signature = Signature.getInstance(JvmCommonCrypto.SIGNATURE_ALGORITHM).apply {
      initSign(keypair.private)
      update(data)
    }.sign()

    Signature.getInstance(JvmCommonCrypto.SIGNATURE_ALGORITHM).apply {
      initVerify(keypair.public)
      update(data)

      assertTrue(verify(signature))
    }
  }

  @Test
  fun generateEphemeralKeypair() {
  }

  @Test
  fun decodePublicKey() {

  }

  @Test
  fun keyDerivation() {
  }
}