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

package com.google.aliro.core

import com.google.aliro.crypto.AliroCrypto
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class AliroIdentifierTest {
  private val crypto = mockk<AliroCrypto>()

  @Test
  fun `identifiers have a fixed size`() {
    val tooLong =
      HexUtil.parseHex("e84842750262ac99a4402d5eb900de3cb4bd845c5f6ee2e423bcf5847ab7599c")
    assertThrows(IllegalArgumentException::class.java) {
      AliroIdentifier(tooLong)
    }

    val tooShort = HexUtil.parseHex("de3c")
    assertThrows(IllegalArgumentException::class.java) {
      AliroIdentifier(tooShort)
    }

    val justRight = HexUtil.parseHex(IDENTIFIER)
    AliroIdentifier(justRight)
  }

  @Test
  fun `identifiers can be randomly initialized`() {
    every { crypto.randomBytes(16) } returns HexUtil.parseHex(IDENTIFIER)

    val rand = AliroIdentifier.randomIdentifier(crypto)
    assertArrayEquals(HexUtil.parseHex(IDENTIFIER), rand.toBytes())
  }

  companion object {
    const val IDENTIFIER = "650c1b412437a17d7db10b4192283619"
  }
}