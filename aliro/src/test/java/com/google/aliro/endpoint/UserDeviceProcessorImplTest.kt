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

import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroErrorCode
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Transaction
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.messages.AliroCommand
import com.google.aliro.messages.AliroResponse
import com.google.aliro.messages.Auth0Command
import com.google.aliro.messages.Auth1Command
import com.google.aliro.messages.ControlFlowCommand
import com.google.aliro.messages.ControlFlowCommandTest
import com.google.aliro.messages.ErrorResponse
import com.google.aliro.messages.ExpeditedStandard
import com.google.aliro.messages.SelectCommand
import com.google.aliro.messages.SelectCommandTest
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class UserDeviceProcessorImplTest {
  private val context = mockk<AliroUserDeviceContext>()
  private val logger = mockk<AliroLogger>(relaxed = true)
  private val crypto = JvmCryptoImpl()

  @Before
  fun init() {
    every { context.crypto } returns crypto
    every { context.logger } returns logger
  }

  @Test
  fun `parseApduCommand returns the appropriately parsed command`() {
    val processor = UserDeviceProcessorImpl(context)

    assertEquals(
      SelectCommand::class,
      processor.parseApduCommand(HexUtil.parseHex(SelectCommandTest.SELECT_COMMAND_HEX))::class
    )

    assertEquals(
      Auth0Command::class,
      processor.parseApduCommand(HexUtil.parseHex(ExpeditedStandard.AUTH0_COMMAND))::class
    )

    assertEquals(
      Auth1Command::class,
      processor.parseApduCommand(HexUtil.parseHex(ExpeditedStandard.AUTH1_COMMAND))::class
    )

    assertEquals(
      ControlFlowCommand::class,
      processor.parseApduCommand(HexUtil.parseHex(ControlFlowCommandTest.SUCCESS))::class
    )
  }

  @Test
  fun `parseApduCommand throws an error when an unknown command is presented`() {
    val processor = UserDeviceProcessorImpl(context)

    assertThrows(IllegalArgumentException::class.java) {
      processor.parseApduCommand(byteArrayOf(0x10, 0x00, 0x00, 0x00))
    }
  }

  @Test
  fun `processCommand processes a command`() {
    val processor = UserDeviceProcessorImpl(context)
    val command = mockk<AliroCommand>()
    val response = mockk<AliroResponse>()

    every { command.process(any()) } returns response

    assertEquals(response, processor.processCommand(command))
  }

  @Test
  fun `processCommand returns errors when there are thrown errors`() {
    val processor = UserDeviceProcessorImpl(context)
    val command = mockk<AliroCommand>()
    val error = AliroError(AliroErrorCode.GENERIC_ERROR, "test")

    every { command.process(any()) } throws error

    assertEquals(ErrorResponse(error.aliroErrorCode), processor.processCommand(command))
  }

  @Test
  fun `onDeselected stops the active transaction`() {
    val processor = UserDeviceProcessorImpl(context)
    val transaction = mockk<Transaction>()
    every { context.transaction } returns transaction
    every { transaction.stop() } just runs

    processor.onDeselected()

    verify { transaction.stop() }
  }
}
