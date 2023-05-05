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

package com.google.aliro.endpoint

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.messages.CommonVectors
import com.google.aliro.publicKeyFromHex
import com.google.aliro.toAliroIdentifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KnownReaderGroupTest {
  @Test
  fun `toString contains useful information`() {
    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    readerGroup.toString().let {
      assertTrue(it.lowercase().contains(CommonVectors.READER_GROUP_ID))
      assertTrue(it.contains("82401520193746007876105374358375870546835552404825763255887435122697107523087"))
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val readerGroup = KnownReaderGroup(
      readerGroupIdentifier = CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      readerPublicKey = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    assertEquals(
      readerGroup,
      KnownReaderGroup(
        readerGroupIdentifier = CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
        readerPublicKey = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
      )
    )

    assertEquals(
      readerGroup.hashCode(),
      KnownReaderGroup(
        readerGroupIdentifier = CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
        readerPublicKey = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
      ).hashCode()
    )

    // readerGroupIdentifier
    assertNotEquals(
      readerGroup,
      KnownReaderGroup(
        readerGroupIdentifier = AliroIdentifier(ByteArray(16)),
        readerPublicKey = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
      )
    )

    // readerPublicKey
    assertNotEquals(
      readerGroup,
      KnownReaderGroup(
        readerGroupIdentifier = CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
        readerPublicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY)
      )
    )
  }
}
