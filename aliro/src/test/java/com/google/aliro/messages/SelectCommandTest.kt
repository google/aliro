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

import com.google.aliro.commandFromHex
import com.google.aliro.core.SelectDone
import com.google.aliro.core.Transaction
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.aliro.endpoint.UserDeviceDatabase
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.HexUtil.parseHex
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class SelectCommandTest {
  private val mockContext = mockk<AliroUserDeviceContext>()
  private val mockUserDeviceDatabase = mockk<UserDeviceDatabase>()
  private val crypto = mockk<JvmCryptoImpl>()
  private val transaction = mockk<Transaction>()

  @Before
  fun init() {
    every { mockContext.crypto } returns crypto
    every { mockContext.database } returns mockUserDeviceDatabase
    every { mockContext.transaction } returns transaction
    every { transaction.moveToState(any()) } just runs

    every { crypto.decodePublicKey(any()) } answers { callOriginal() }
    every { crypto.keyDerivation(any(), any(), any(), any()) } answers { callOriginal() }
  }

  @Test
  fun `toBytes outputs an expected representation`() {
    val select = SelectCommand(parseHex(TEST_AID))
    val expected = parseHex(SELECT_COMMAND_HEX)

    assertArrayEquals(expected, select.toBytes())

    assertEquals(select, SelectCommand.parse(ApduCommand.parse(expected)))
  }

  @Test
  fun `process moves the transaction to the correct state`() {
    val expected = SelectResponse()

    assertEquals(expected, SelectCommand(parseHex(TEST_AID)).process(mockContext))

    verify {
      transaction.moveToState(SelectDone)
    }
  }

  @Test
  fun `parse of the test vectors yields an expected result`() {
    val expected = SelectCommand(parseHex(CommonVectors.AID))

    assertEquals(expected, SelectCommand.parse(commandFromHex(CommonVectors.SELECT_COMMAND)))
  }

  @Test
  fun `toString returns a useful representation`() {
    val select = SelectCommand(parseHex(TEST_AID))

    select.toString().let {
      assertTrue(it.contains("SelectCommand"))
      assertTrue(it.contains(TEST_AID))
    }
  }

  @Test
  fun `equals and hashCode function properly`() {
    val select1 = SelectCommand(parseHex(TEST_AID))
    val select2 = SelectCommand(parseHex(CommonVectors.AID))

    assertEquals(select1, SelectCommand(parseHex(TEST_AID)))
    assertEquals(select1.hashCode(), SelectCommand(parseHex(TEST_AID)).hashCode())

    assertNotEquals(select1, select2)
    assertNotEquals(select1.hashCode(), select2.hashCode())
  }

  companion object {
    const val TEST_AID = "001122334455"
    const val SELECT_COMMAND_HEX = "00A4 0400 06 001122334455 00"
  }
}
