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
import com.google.aliro.core.AliroInstructions
import com.google.aliro.messages.AliroCommand
import com.google.aliro.messages.AliroResponse
import com.google.aliro.messages.Auth0Command
import com.google.aliro.messages.Auth1Command
import com.google.aliro.messages.ControlFlowCommand
import com.google.aliro.messages.ErrorResponse
import com.google.aliro.messages.SelectCommand
import com.google.nfc.apdu.ApduCommand

/**
 * Process APDU commands as a user device. The user device stores credentials and communicates
 * with the reader.
 */
interface UserDeviceProcessor {
  /**
   * Parse the [encoded] APDU packet into an [AliroCommand]. This can then be processed by passing
   * the command with [processCommand].
   */
  fun parseApduCommand(encoded: ByteArray): AliroCommand

  /**
   * Process the given [command], returning an [AliroResponse].
   */
  fun processCommand(command: AliroCommand): AliroResponse

  /**
   * Call this when the NFC tag has been deselected.
   */
  fun onDeselected()
}

class UserDeviceProcessorImpl(private val context: AliroUserDeviceContext) : UserDeviceProcessor {
  override fun parseApduCommand(encoded: ByteArray): AliroCommand {
    val command = ApduCommand.parse(encoded)

    return when (command.instruction) {
      AliroInstructions.SELECT -> SelectCommand.parse(command)
      AliroInstructions.AUTH0 -> Auth0Command.parse(context.crypto, command)
      AliroInstructions.AUTH1 -> Auth1Command.parse(command)
      AliroInstructions.CONTROL_FLOW -> ControlFlowCommand.parse(command)

      else -> throw IllegalArgumentException("Unknown command: ${Integer.toHexString(command.instruction.toInt() and 0xff)}")
    }
  }

  override fun processCommand(command: AliroCommand): AliroResponse {
    val result = try {
      context.logger.logDebug("Processing command: $command")
      command.process(context)
    } catch (e: AliroError) {
      context.logger.logError("Error processing command $command", e)
      return ErrorResponse(e.aliroErrorCode)
    }

    context.logger.logDebug("Sending result: $result")

    return result
  }

  override fun onDeselected() {
    context.transaction.stop()
  }
}
