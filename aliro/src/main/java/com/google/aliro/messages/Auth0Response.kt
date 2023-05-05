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

import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.messages.AliroResponse.Companion.SW1_NO_FURTHER_QUALIFICATION
import com.google.aliro.reader.AliroReaderContext
import com.google.aliro.tlv.optionalTag
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import java.security.PublicKey
import java.util.Objects

class Auth0Response(val endpointEPk: PublicKey, val cryptogram: Cryptogram? = null) :
  AliroResponse {
  override fun toBytes(): ByteArray {
    val data = BerTlvBuilder().apply {
      addBytes(BerTag(TAG_ENDPOINT_EPK), endpointEPk.encodeBasic())
      cryptogram?.let {
        addBytes(BerTag(TAG_CRYPTOGRAM), it.toBytes())
      }
    }.buildArray()

    return ApduResponse(SW1_NO_FURTHER_QUALIFICATION, 0x00, data).serialize()
  }

  override fun toString() = "Auth0Response(endpointEPk=$endpointEPk, cryptogram=$cryptogram)"

  override fun hashCode() = Objects.hash(endpointEPk, cryptogram)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Auth0Response) return false

    if (endpointEPk != other.endpointEPk) return false

    return cryptogram == other.cryptogram
  }

  companion object {
    private const val TAG_ENDPOINT_EPK = 0x86
    private const val TAG_CRYPTOGRAM = 0x9D

    @JvmStatic
    fun parse(aliroContext: AliroReaderContext, apduResponse: ApduResponse): Auth0Response {
      val tlv = BerTlvParser().parse(apduResponse.data)

      val endpointEpk = tlv.requireTag(TAG_ENDPOINT_EPK).let { endpointEpkTag ->
        aliroContext.crypto.decodePublicKey(endpointEpkTag.bytesValue)
      }

      val cryptogram = tlv.optionalTag(TAG_CRYPTOGRAM)?.let { cryptogramTag ->
        Cryptogram(cryptogramTag.bytesValue)
      }

      return Auth0Response(endpointEpk, cryptogram)
    }
  }
}
