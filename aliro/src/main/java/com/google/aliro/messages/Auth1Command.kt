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
import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroErrorCode
import com.google.aliro.core.AliroInstructions
import com.google.aliro.core.ApduClass
import com.google.aliro.core.Auth0Done
import com.google.aliro.core.Auth1Done
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.SecureChannelKeys
import com.google.aliro.core.toHex
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.crypto.xByteArray
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.aliro.tlv.optionalTag
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import com.payneteasy.tlv.HexUtil
import java.util.Objects
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

/**
 * An AUTH1 command.
 *
 * If [isEndpointPublicKey] is `false`, the [Auth1Response] must contain the `key_slot`.
 * Otherwise the response must contain the `endpointPubK`.
 */
class Auth1Command(
  val isEndpointPublicKey: Boolean,
  val readerSignature: ReaderSignature,
  val certificateData: ByteArray? = null,
) : AliroCommand {
  override fun process(context: AliroUserDeviceContext): Auth1Response {
    // based on Figure 8-13
    val log = context.logger
    log.logDebug("Processing AUTH1: $this")
    val state = context.transaction.state

    if (state !is Auth0Done) {
      throw AliroError(AliroErrorCode.GENERIC_ERROR, "AUTH0 must be completed first")
    }

    // check if standard transactions are allowed on this interface, return 0x6900 if not

    val endpoint = state.endpoint
    val readerGroup =
      context.database.findReaderGroup(state.readerIdentifier.groupIdentifier) ?: run {
        log.logDebug("Using dummy reader")
        context.database.dummyReaderGroup()
      }

    log.logDebug("Reader found for group ID ${state.readerIdentifier.groupIdentifier}")
    log.logDebug("Reader info: ${state.readerIdentifier}")

    log.logDebug("Current transaction state: $state")
    log.logDebug("Reader: $readerGroup")

    log.logDebug("Reader Identifier: ${HexUtil.toFormattedHexString(state.readerIdentifier.toBytes())}")
    log.logDebug("Endpoint E public key X value: ${HexUtil.toFormattedHexString(state.endpointEKeypair.public.xByteArray)}")
    log.logDebug("Reader E public key X value: ${HexUtil.toFormattedHexString(state.readerEpk.xByteArray)}")
    log.logDebug("Transaction ID: ${HexUtil.toFormattedHexString(state.transactionIdentifier.toBytes())}")

    val data = generateAuthenticationData(
      readerIdentifier = state.readerIdentifier,
      endpointEPublicKey = state.endpointEKeypair.public,
      readerEPublicKey = state.readerEpk,
      transactionIdentifier = state.transactionIdentifier,
      usage = READER_USAGE,
    )

    log.logDebug("Verify reader signature: data ${HexUtil.toFormattedHexString(data)}")
    log.logDebug("Verify reader signature: ${HexUtil.toFormattedHexString(readerSignature.signature.bytes)}")

    log.logDebug("Using reader public key: ${HexUtil.toFormattedHexString(readerGroup.readerPublicKey.encodeBasic())}")
    val signatureValid = context.crypto.verifySignature(
      data = data,
      publicKey = readerGroup.readerPublicKey,
      signature = readerSignature.signature.bytes
    )

    if (!signatureValid) {
      context.logger.logError("Invalid reader signature")
      throw AliroError(AliroErrorCode.GENERIC_ERROR, "Invalid reader signature")
    } else {
      context.logger.logDebug("Reader signature is valid")
    }

    val kDh = context.crypto.diffieHellmanKeyDerivation(
      remotePublicKey = state.readerEpk,
      secretKey = state.endpointEKeypair.private,
      transactionIdentifier = state.transactionIdentifier
    )
    context.logger.logDebug("Diffie Hellman key: ${HexUtil.toFormattedHexString(kDh)}")

    val versionBytes = VersionsImpl.toByteArray(state.protocolVersion)

    val derivedKeys = context.crypto.keyDerivation(
      inputKeyingMaterial = kDh,
      info = auth1Info(
        readerEPk = state.readerEpk,
        endpointEPk = state.endpointEKeypair.public,
        transactionIdentifier = state.transactionIdentifier,
        flag = state.flag,
        versionBytes = versionBytes,
        type = KEY_DERIVATION_TYPE_VOLATILE,
        supportedVersions = context.versions.supportedVersions,
      ),
      salt = ByteArray(32),
      outputSize = 160,
    )

    val secureChannelState = state.secureChannelState.copy(
      keys = SecureChannelKeys(
        exchangeSkReader = SecretKeySpec(derivedKeys.sliceArray(0 until 32), "AES"),
        exchangeSkDevice = SecretKeySpec(derivedKeys.sliceArray(32 until 64), "AES"),
        stepUpSk = SecretKeySpec(derivedKeys.sliceArray(64 until 96), "AES"),
        bleSk = SecretKeySpec(derivedKeys.sliceArray(96 until 128), "AES"),
        urSk = SecretKeySpec(derivedKeys.sliceArray(128 until 160), "AES"),
      ),
    )

    val keyMaterial = context.crypto.keyDerivation(
      inputKeyingMaterial = kDh,
      info = auth1Info(
        readerEPk = state.readerEpk,
        endpointEPk = state.endpointEKeypair.public,
        transactionIdentifier = state.transactionIdentifier,
        flag = state.flag,
        versionBytes = versionBytes,
        type = KEY_DERIVATION_TYPE_PERSISTENT,
        supportedVersions = context.versions.supportedVersions,
      ),
      salt = ByteArray(32),
      outputSize = 32,
    )
    val kPersistent = keyMaterial.slice(0 until 32).toByteArray()

    log.logDebug(
      "Storing persistent key for reader ID <${state.readerIdentifier}>: ${
        HexUtil.toFormattedHexString(kPersistent)
      }"
    )
    context.database.storePersistentKey(
      readerIdentifier = state.readerIdentifier,
      kPersistent = FixedByteArray(kPersistent)
    )

    val endpointSig = generateAuthenticationSignature(
      crypto = context.crypto,
      signingPrivateKey = endpoint.endpointKeypair.private,
      readerIdentifier = state.readerIdentifier,
      readerEPublicKey = state.readerEpk,
      endpointEPublicKey = state.endpointEKeypair.public,
      transactionIdentifier = state.transactionIdentifier,
      usage = ENDPOINT_USAGE,
    )

    val responsePlaintext = Auth1ResponsePlaintext(
      endpointSignature = FixedByteArray(endpointSig),
      endpointPk = endpoint.endpointKeypair.public,
      keySlot = null,
    )

    val (newSecureChannelState, response) = Auth1Response.encrypt(
      crypto = context.crypto,
      secureChannelState = secureChannelState,
      plaintext = responsePlaintext
    )

    context.transaction.moveToState(
      Auth1Done(
        secureChannelState = newSecureChannelState,
        transactionIdentifier = state.transactionIdentifier,
        readerEpk = state.readerEpk,
        readerIdentifier = state.readerIdentifier,
        endpoint = state.endpoint,
        endpointEKeypair = state.endpointEKeypair,
        flag = state.flag,
        protocolVersion = state.protocolVersion,
      )
    )

    log.logDebug("AUTH1 success!")

    return response
  }

  override fun toString() =
    "Auth1Command(isEndpointPk=$isEndpointPublicKey, readerSig=$readerSignature, certificateData=${certificateData?.toHex()})"

  override fun hashCode() =
    Objects.hash(isEndpointPublicKey, readerSignature, certificateData.contentHashCode())

  override fun toBytes(): ByteArray {
    val data = BerTlvBuilder().apply {
      addByte(BerTag(TAG_COMMAND_PARAMETERS), if (isEndpointPublicKey) 0x01 else 0x00)
      addBytes(BerTag(TAG_READER_SIG), readerSignature.signature.bytes)

      if (certificateData != null) {
        addBytes(BerTag(TAG_CERTIFICATE_DATA), certificateData)
      }
    }.buildArray()

    return ApduCommand(
      commandClass = ApduClass.PROPRIETARY,
      instruction = AliroInstructions.AUTH1,
      parameter1 = 0x00,
      parameter2 = 0x00,
      data = data,
      maxExpectedResponseLength = 256
    ).serialize()
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Auth1Command) return false

    if (isEndpointPublicKey != other.isEndpointPublicKey) return false
    if (readerSignature != other.readerSignature) return false
    if (certificateData != null) {
      if (other.certificateData == null) return false
      if (!certificateData.contentEquals(other.certificateData)) return false
    } else if (other.certificateData != null) return false

    return true
  }

  companion object {
    private const val TAG_COMMAND_PARAMETERS = 0x41
    private const val TAG_READER_SIG = 0x9E
    private const val TAG_CERTIFICATE_DATA = 0x90

    internal const val KEY_DERIVATION_TYPE_PERSISTENT = "Persistent"
    internal const val KEY_DERIVATION_TYPE_VOLATILE = "Volatile"

    @JvmStatic
    fun parse(apduCommand: ApduCommand): Auth1Command {
      val tlv = BerTlvParser().parse(apduCommand.data)

      val isEndpointPublicKey = (tlv.requireTag(TAG_COMMAND_PARAMETERS).bytesValue[0] and 0x01) > 0

      return Auth1Command(
        isEndpointPublicKey = isEndpointPublicKey,
        readerSignature = ReaderSignature(tlv.requireTag(TAG_READER_SIG).bytesValue),
        certificateData = tlv.optionalTag(TAG_CERTIFICATE_DATA)?.bytesValue
      )
    }
  }
}
