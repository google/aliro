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
import com.google.aliro.tlv.optionalTag
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import java.util.Objects

class ControlFlowCommand internal constructor(
  val s1Parameter: Byte,
  val s2Parameter: Byte,
  val domainSpecificData: ByteArray? = null,
) : AliroCommand {
  constructor(success: Boolean) : this(
    s1Parameter = if (success) 0x01 else 0x00,
    s2Parameter = 0x00,
    domainSpecificData = null
  )

  override fun process(context: AliroUserDeviceContext): ControlFlowResponse {
    context.transaction.moveToState(SelectDone)

    return ControlFlowResponse()
  }

  override fun toBytes(): ByteArray = ApduCommand(
    commandClass = ApduClass.PROPRIETARY,
    instruction = AliroInstructions.CONTROL_FLOW,
    parameter1 = 0x00,
    parameter2 = 0x00,
    data = BerTlvBuilder().apply {
      addByte(BerTag(TAG_S1_PARAMETER), s1Parameter)
      addByte(BerTag(TAG_S2_PARAMETER), s2Parameter)

      if (domainSpecificData != null) {
        addBytes(BerTag(TAG_DOMAIN_SPECIFIC_DATA), domainSpecificData)
      }
    }.buildArray(),
    maxExpectedResponseLength = 0
  ).serialize()

  override fun hashCode() =
    Objects.hash(s1Parameter, s2Parameter, domainSpecificData?.contentHashCode())

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ControlFlowCommand) return false

    if (s1Parameter != other.s1Parameter) return false
    if (s2Parameter != other.s2Parameter) return false
    if (domainSpecificData != null) {
      if (other.domainSpecificData == null) return false
      if (!domainSpecificData.contentEquals(other.domainSpecificData)) return false
    } else if (other.domainSpecificData != null) return false

    return true
  }

  companion object {
    @JvmStatic
    fun stepUp() = ControlFlowCommand(
      S1_DOMAIN_SPECIFIC.toByte(),
      S2_STEP_UP.toByte(),
    )

    @JvmStatic
    fun parse(apduCommand: ApduCommand): ControlFlowCommand {
      val tlv = BerTlvParser().parse(apduCommand.data)

      return ControlFlowCommand(
        s1Parameter = tlv.requireTag(TAG_S1_PARAMETER).bytesValue[0],
        s2Parameter = tlv.requireTag(TAG_S2_PARAMETER).bytesValue[0],
        domainSpecificData = tlv.optionalTag(TAG_DOMAIN_SPECIFIC_DATA)?.bytesValue,
      )
    }

    private const val S1_DOMAIN_SPECIFIC = 0x40
    private const val S2_STEP_UP = 0xA0
    private const val TAG_S1_PARAMETER = 0x41
    private const val TAG_S2_PARAMETER = 0x42
    private const val TAG_DOMAIN_SPECIFIC_DATA = 0x43
  }
}
