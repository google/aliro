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

import com.google.aliro.core.AliroInstructions
import com.google.aliro.core.ApduClass
import com.google.aliro.core.SelectDone
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.HexUtil
import java.util.Objects

class SelectCommand(val applicationId: ByteArray) : AliroCommand {
  override fun process(context: AliroUserDeviceContext): SelectResponse {
    context.transaction.moveToState(SelectDone)

    return SelectResponse()
  }

  override fun toBytes() = ApduCommand(
    commandClass = ApduClass.INTER_INDUSTRY,
    instruction = AliroInstructions.SELECT,
    parameter1 = 0x04,
    parameter2 = 0x00,
    data = applicationId,
    maxExpectedResponseLength = 256
  ).serialize()

  override fun toString() = "SelectCommand(aid=${HexUtil.toHexString(applicationId)})"

  override fun hashCode() = Objects.hash(applicationId.contentHashCode())

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is SelectCommand) return false

    return applicationId.contentEquals(other.applicationId)
  }

  companion object {
    // TODO set correct AID
    private const val INTERIM_ALIRO_AID = "F0006B7369000002"

    @JvmField
    val AID: ByteArray = HexUtil.parseHex(INTERIM_ALIRO_AID)

    @JvmStatic
    fun parse(apduCommand: ApduCommand) = SelectCommand(apduCommand.data)
  }
}
