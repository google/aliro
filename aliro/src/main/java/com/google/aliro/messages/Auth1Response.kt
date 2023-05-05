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

import com.google.aliro.core.AliroSerializable
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.SecureChannelState
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.endpoint.AliroContext
import com.google.aliro.tlv.optionalTag
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import com.payneteasy.tlv.HexUtil
import java.security.PublicKey
import java.util.Objects

class Auth1Response(val sw1: Byte, val sw2: Byte, val ciphertext: ByteArray) : AliroResponse {
  override fun toBytes(): ByteArray {
    return ApduResponse(sw1, sw2, ciphertext).serialize()
  }

  fun decrypt(
    context: AliroContext,
    secureChannelState: SecureChannelState
  ): Auth1ResponsePlaintext {
    val (_, responseBytes) = context.crypto.responseDecryption(secureChannelState, ciphertext)

    return Auth1ResponsePlaintext.parse(context.crypto, responseBytes)
  }

  override fun toString() =
    "Auth1Response(sw1=$sw1, sw2=$sw2, ciphertext=${HexUtil.toHexString(ciphertext)})"

  override fun hashCode() = Objects.hash(sw1, sw2, ciphertext.contentHashCode())

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Auth1Response) return false

    if (sw1 != other.sw1) return false
    if (sw2 != other.sw2) return false

    return ciphertext.contentEquals(other.ciphertext)
  }

  companion object {
    @JvmStatic
    fun parse(apduResponse: ApduResponse) =
      Auth1Response(apduResponse.sw1, apduResponse.sw2, apduResponse.data)

    fun encrypt(
      crypto: AliroCrypto,
      secureChannelState: SecureChannelState,
      plaintext: Auth1ResponsePlaintext
    ): Pair<SecureChannelState, Auth1Response> {
      val (newSecureChannelState, ciphertextAndMac) = crypto.responseEncryption(
        channelState = secureChannelState,
        data = plaintext.toBytes()
      )
      val response =
        Auth1Response(AliroResponse.SW1_NO_FURTHER_QUALIFICATION, 0x00, ciphertextAndMac)

      return Pair(newSecureChannelState, response)
    }
  }
}

class Auth1ResponsePlaintext(
  val endpointSignature: FixedByteArray,
  val endpointPk: PublicKey?,
  val keySlot: FixedByteArray?,
) : AliroSerializable {
  override fun toString() =
    "Auth1ResponsePlaintext(endpointSig=${endpointSignature.toHexString()}, endpointPk=$endpointPk, keySlot=${keySlot?.toHexString()})"

  override fun hashCode() = Objects.hash(endpointSignature, endpointPk, keySlot)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Auth1ResponsePlaintext) return false

    if (endpointSignature != other.endpointSignature) return false
    if (endpointPk != other.endpointPk) return false

    return keySlot == other.keySlot
  }

  override fun toBytes(): ByteArray = BerTlvBuilder().apply {
    if (endpointPk != null) {
      addBytes(BerTag(TAG_ENDPOINT_PK), endpointPk.encodeBasic())
    }

    if (keySlot != null) {
      addBytes(BerTag(TAG_KEY_SLOT), keySlot.bytes)
    }

    addBytes(BerTag(TAG_ENDPOINT_SIG), endpointSignature.bytes)
    addBytes(BerTag(TAG_SIGNALING_BITMAP), byteArrayOf(0x00))
  }.buildArray()

  companion object {
    private const val TAG_ENDPOINT_PK = 0x5A
    private const val TAG_ENDPOINT_SIG = 0x9E
    private const val TAG_KEY_SLOT = 0x4E
    private const val TAG_SIGNALING_BITMAP = 0x5E

    @JvmStatic
    fun parse(crypto: AliroCrypto, byteArray: ByteArray): Auth1ResponsePlaintext {
      val berTlv = BerTlvParser().parse(byteArray)

      return Auth1ResponsePlaintext(
        endpointSignature = FixedByteArray(berTlv.requireTag(TAG_ENDPOINT_SIG).bytesValue),
        endpointPk = berTlv.optionalTag(TAG_ENDPOINT_PK)?.bytesValue?.let {
          crypto.decodePublicKey(it)
        },
        keySlot = berTlv.optionalTag(TAG_KEY_SLOT)
          ?.let { FixedByteArray(it.bytesValue) }
      )
    }
  }
}
