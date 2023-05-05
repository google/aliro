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

import com.google.aliro.assertEqualsHex
import com.google.aliro.core.SelectDone
import com.google.aliro.core.Transaction
import com.google.aliro.core.b
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ControlFlowCommandTest {

  @Test
  fun `ControlFlowCommand deserializes`() {
    assertEqualsHex(SUCCESS, ControlFlowCommand(true).toBytes())
  }

  @Test
  fun `ControlFlowCommand round-trips`() {
    val expected = ControlFlowCommand(
      s1Parameter = b(0x01),
      s2Parameter = b(0x23),
      domainSpecificData = HexUtil.parseHex(DOMAIN_SPECIFIC_DATA)
    )
    assertEquals(expected, ControlFlowCommand.parse(ApduCommand.parse(expected.toBytes())))
  }

  @Test
  fun `ControlFlowCommand equals and hashcode function`() {
    assertEquals(ControlFlowCommand(true), ControlFlowCommand(true))
    assertEquals(ControlFlowCommand(false), ControlFlowCommand(false))

    assertEquals(
      ControlFlowCommand(s1Parameter = 0x40, b(0xA0)),
      ControlFlowCommand(s1Parameter = 0x40, b(0xA0)),
    )

    assertEquals(
      ControlFlowCommand(s1Parameter = 0x40, b(0x80), byteArrayOf(0xFA.toByte(), 0xCE.toByte())),
      ControlFlowCommand(s1Parameter = 0x40, b(0x80), byteArrayOf(0xFA.toByte(), 0xCE.toByte())),
    )

    assertEquals(
      ControlFlowCommand(true).hashCode(),
      ControlFlowCommand(true).hashCode()
    )
  }

  @Test
  fun `process changes transaction state and returns a response`() {
    val context = mockk<AliroUserDeviceContext>()
    val transaction = mockk<Transaction>()

    every { context.transaction } returns transaction
    every { transaction.moveToState(any()) } just runs

    val command = ControlFlowCommand(true)
    val response = command.process(context)

    assertEquals(ControlFlowResponse(), response)

    verify {
      transaction.moveToState(SelectDone)
    }
  }

  @Test
  fun `ControlFlowCommand step up`() {
    assertEqualsHex(STEP_UP, ControlFlowCommand.stepUp().toBytes())
  }

  companion object {
    const val SUCCESS = "803C 00 00 06 410101 420100"
    const val STEP_UP = "803C 00 00 06 410140 4201A0"
    const val DOMAIN_SPECIFIC_DATA = "CAFE F00D"
  }
}