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

package com.google.aliro.android.sampleapp

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

@RunWith(JUnit4::class)
class InMemoryDbTest {
  private val crypto = mockk<AliroCrypto>()
  private val mockKeypair = mockk<KeyPair>()
  private val mockPublicKey = mockk<PublicKey>()

  init {
    every { crypto.generateEphemeralKeypair() } returns mockKeypair
    every { mockKeypair.public } returns mockPublicKey
    val count = slot<Int>()
    every { crypto.randomBytes(capture(count)) } answers { ByteArray(count.captured) } // all 0x00
  }

  @Test
  fun `findReader finds a previously stored reader`() {
    val db = InMemoryDb(crypto)

    val publicKey = mockk<PublicKey>()
    val privateKey = mockk<PrivateKey>()
    val keypair = KeyPair(publicKey, privateKey)
    val endpoint = Endpoint(keypair)

    db.storeReaderGroup(endpoint, KnownReaderGroup(groupIdentifier, publicKey))

    val readerGroup = db.findReaderGroup(groupIdentifier)

    assertNotNull(readerGroup)
    assertEquals(publicKey, readerGroup?.readerPublicKey)
    assertEquals(groupIdentifier, readerGroup?.readerGroupIdentifier)
  }

  @Test
  fun `findEndpoint finds a previously stored endpoint`() {

  }

  companion object {
    val groupIdentifier = AliroIdentifier(HexUtil.parseHex("e4e0cc7e3511738cf37b089750fabea0"))
  }
}