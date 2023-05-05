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

import com.google.aliro.VersionsImpl
import com.google.aliro.core.toHex
import com.google.aliro.messages.AliroResponse.Companion.SW1_NO_FURTHER_QUALIFICATION
import com.google.aliro.tlv.optionalTag
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import java.util.Objects

class SelectResponse internal constructor(
  val selectedAid: ByteArray,
  val supportedVersions: ByteArray,
  val type: ByteArray,
  val capabilities: ByteArray? = null,
) : AliroResponse {
  constructor() : this(
    selectedAid = SelectCommand.AID,
    supportedVersions = VersionsImpl.SUPPORTED_VERSIONS,
    type = byteArrayOf(0x00, 0x00)
  )

  private fun responseBody(): ByteArray = BerTlvBuilder().apply {
    addBytes(BerTag(TAG_FCI), BerTlvBuilder().apply {
      addBytes(BerTag(TAG_SELECTED_AID), selectedAid)
      addBytes(BerTag(TAG_VERSIONS_AND_CAPABILITIES), BerTlvBuilder().apply {
        addBytes(BerTag(TAG_TYPE), type)
        addBytes(BerTag(TAG_SUPPORTED_PROTOCOL_VERSIONS), supportedVersions)
        if (capabilities != null) {
          addBytes(BerTag(TAG_CAPABILITIES), capabilities)
        }
        // capabilities is optional and not clear in 0.7
      }.buildArray())
    }.buildArray())
  }.buildArray()

  override fun toBytes() =
    ApduResponse(SW1_NO_FURTHER_QUALIFICATION, 0x00, responseBody()).serialize()

  override fun hashCode() = Objects.hash(
    selectedAid.contentHashCode(),
    supportedVersions.contentHashCode(),
    type.contentHashCode(),
    capabilities.contentHashCode(),
  )

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is SelectResponse) return false

    if (!selectedAid.contentEquals(other.selectedAid)) return false
    if (!supportedVersions.contentEquals(other.supportedVersions)) return false
    if (!type.contentEquals(other.type)) return false
    if (capabilities != null) {
      if (other.capabilities == null) return false
      if (!capabilities.contentEquals(other.capabilities)) return false
    } else if (other.capabilities != null) return false

    return true
  }

  override fun toString() =
    "SelectResponse(AID=${selectedAid.toHex()}, supportedVersions=${supportedVersions.toHex()}, type=${type.toHex()}, capabilities=${capabilities?.toHex()}"

  companion object {
    private const val TAG_FCI = 0x6F
    private const val TAG_SELECTED_AID = 0x84
    private const val TAG_VERSIONS_AND_CAPABILITIES = 0xA5
    private const val TAG_TYPE = 0x80
    private const val TAG_SUPPORTED_PROTOCOL_VERSIONS = 0x81
    private const val TAG_CAPABILITIES = 0x82

    @JvmStatic
    fun parse(apdu: ApduResponse): SelectResponse {
      val parser = BerTlvParser().parse(apdu.data)
      val fci = parser.requireTag(TAG_FCI)
      val selectedAid = fci.requireTag(TAG_SELECTED_AID).bytesValue
      val versionsAndCapabilities = parser.requireTag(TAG_VERSIONS_AND_CAPABILITIES)
      val supportedVersions =
        versionsAndCapabilities.requireTag(TAG_SUPPORTED_PROTOCOL_VERSIONS).bytesValue
      val type = versionsAndCapabilities.requireTag(TAG_TYPE).bytesValue
      val capabilities = versionsAndCapabilities.optionalTag(TAG_CAPABILITIES)?.bytesValue

      return SelectResponse(
        selectedAid = selectedAid,
        supportedVersions = supportedVersions,
        type = type,
        capabilities = capabilities
      )
    }
  }
}
