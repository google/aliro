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

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.FixedByteArray
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors
import com.google.aliro.messages.ExpeditedFast
import com.google.aliro.publicKeyFromHex
import com.google.aliro.toAliroIdentifier
import com.payneteasy.tlv.HexUtil.parseHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.interfaces.ECPublicKey

class NeedAuth1Test {
  private val needAuth1 = NeedAuth1(
    protocolVersion = CommonVectors.PROTOCOL_VERSION,
    supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
    readerEKeypair = keypairFromHex(
      ExpeditedFast.READER_E_PUBLIC_KEY,
      ExpeditedFast.READER_E_PRIVATE_KEY
    ),
    endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
    transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
    flag = FixedByteArray(parseHex("0101")),
  )

  @Test
  fun `equals and hashCode function as expected`() {
    val second = NeedAuth1(
      protocolVersion = CommonVectors.PROTOCOL_VERSION,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      readerEKeypair = keypairFromHex(
        ExpeditedFast.READER_E_PUBLIC_KEY,
        ExpeditedFast.READER_E_PRIVATE_KEY
      ),
      endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
      transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      flag = FixedByteArray(parseHex("0101")),
    )
    assertEquals(needAuth1, second)
    assertEquals(needAuth1.hashCode(), second.hashCode())

    // protocolVersion
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = 42,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.READER_E_PUBLIC_KEY,
          ExpeditedFast.READER_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        flag = FixedByteArray(parseHex("0101")),
      )
    )

    // supportedVersions
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex("0420"),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.READER_E_PUBLIC_KEY,
          ExpeditedFast.READER_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        flag = FixedByteArray(parseHex("0101")),
      )
    )

    //readerEKeypair
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.DEVICE_E_PUBLIC_KEY,
          ExpeditedFast.DEVICE_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        flag = FixedByteArray(parseHex("0101")),
      )
    )

    // endpointEPk
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.READER_E_PUBLIC_KEY,
          ExpeditedFast.READER_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.READER_E_PUBLIC_KEY),
        transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        flag = FixedByteArray(parseHex("0101")),
      )
    )

    // transactionIdentifier
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.READER_E_PUBLIC_KEY,
          ExpeditedFast.READER_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        transactionIdentifier = AliroIdentifier(ByteArray(16)),
        flag = FixedByteArray(parseHex("0101")),
      )
    )

    // flag
    assertNotEquals(
      needAuth1, NeedAuth1(
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEKeypair = keypairFromHex(
          ExpeditedFast.READER_E_PUBLIC_KEY,
          ExpeditedFast.READER_E_PRIVATE_KEY
        ),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        flag = FixedByteArray(parseHex("0000")),
      )
    )
  }

  @Test
  fun `fun toString contains useful information`() {
    needAuth1.toString().let {
      assertTrue(it.contains("NeedAuth1"))
      assertTrue(it.contains(CommonVectors.SUPPORTED_VERSIONS))
      assertTrue(it.contains((needAuth1.readerEKeypair.public as ECPublicKey).w.affineX.toString()))
      assertTrue(it.contains(ExpeditedFast.TRANSACTION_IDENTIFIER))
      assertTrue(it.contains("0101"))
    }
  }
}