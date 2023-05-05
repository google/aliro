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

package com.google.aliro.reader

import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors
import com.payneteasy.tlv.HexUtil.parseHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.interfaces.ECPublicKey

class ReaderConfigurationTest {
  private val readerConfiguration = ReaderConfiguration(
    identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
    keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
    shouldSendFastTransaction = false,
  )

  @Test
  fun `equals and hashCode function as expected`() {
    assertEquals(
      readerConfiguration,
      ReaderConfiguration(
        identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
        keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
        shouldSendFastTransaction = false,
      )
    )

    assertEquals(
      readerConfiguration.hashCode(),
      ReaderConfiguration(
        identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
        keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
        shouldSendFastTransaction = false,
      ).hashCode()
    )

    // identifier
    assertNotEquals(
      readerConfiguration,
      ReaderConfiguration(
        identifier = ReaderIdentifier(ByteArray(32)),
        keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
        shouldSendFastTransaction = false,
      )
    )

    // keypair
    assertNotEquals(
      readerConfiguration,
      ReaderConfiguration(
        identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
        keypair = keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY),
        shouldSendFastTransaction = false,
      )
    )

    // shouldSendFastTransaction
    assertNotEquals(
      readerConfiguration,
      ReaderConfiguration(
        identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
        keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
        shouldSendFastTransaction = true,
      )
    )
  }

  @Test
  fun `toString contains useful information`() {
    readerConfiguration.toString().let {
      assertTrue(it.contains("ReaderConfiguration"))
      assertTrue(it.contains(CommonVectors.READER_GROUP_ID))
      assertTrue(it.contains(CommonVectors.READER_SUB_GROUP_ID))
      assertTrue(it.contains((readerConfiguration.keypair.public as ECPublicKey).w.affineX.toString()))
      assertTrue(it.contains("shouldSendFastTransaction=false"))
    }
  }
}