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
import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.AliroInstructions
import com.google.aliro.core.ApduClass
import com.google.aliro.core.Auth0FastDone
import com.google.aliro.core.Auth0StandardDone
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.core.SecureChannelKeys
import com.google.aliro.core.SecureChannelState
import com.google.aliro.core.SelectDone
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.crypto.xByteArray
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.aliro.tlv.requireTag
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import com.payneteasy.tlv.BerTlvParser
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.PublicKey
import java.util.Objects
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and


class Auth0Command(
  val isFastTransaction: Boolean,
  val transactionCode: TransactionCode,
  val protocolVersion: Int,
  val readerEPk: PublicKey,
  val readerIdentifier: ReaderIdentifier,
  val transactionIdentifier: AliroIdentifier,
) : AliroCommand {
  override fun toBytes(): ByteArray {
    return ApduCommand(
      commandClass = ApduClass.PROPRIETARY,
      instruction = AliroInstructions.AUTH0,
      parameter1 = 0x00,
      parameter2 = 0x00,
      data = toTlv(
        isFastTransaction = isFastTransaction,
        transactionCode = transactionCode.code,
        protocolVersion = protocolVersion,
        readerEPk = readerEPk,
        transactionIdentifier = transactionIdentifier,
        readerIdentifier = readerIdentifier
      ),
      maxExpectedResponseLength = 256
    ).serialize()
  }

  val parameter1: Byte
    get() = if (isFastTransaction) 0x01 else 0x00

  // This is running on the phone
  override fun process(context: AliroUserDeviceContext): Auth0Response {
    // from figure 8-13
    val log = context.logger

    if (context.transaction.state != SelectDone) {
      throw AliroError(AliroErrorCode.GENERIC_ERROR, "Incorrect transaction state")
    }

    if (!context.versions.isVersionSupported(protocolVersion)) {
      throw AliroError(AliroErrorCode.GENERIC_ERROR, "Unsupported protocol version: $protocolVersion")
    }

    val endpointEphemeralKeyPair = context.crypto.generateEphemeralKeypair()
    val endpoints = context.database.findEndpoints(readerIdentifier.groupIdentifier)

    val endpoint = when (endpoints.size) {
      0 -> run {
        log.logDebug("Using dummy endpoint")
        context.database.dummyEndpoint()
      }

      1 -> endpoints.first()

      // TODO implement the ACWG-chosen resolution here b/295525236
      else -> endpoints.random()
    }

    val flag = FixedByteArray(byteArrayOf(parameter1, transactionCode.code))

    log.logDebug("Endpoint: $endpoint")

    if (!isFastTransaction) {
      log.logDebug("Processing as a Standard transaction")
      context.transaction.moveToState(
        Auth0StandardDone(
          transactionIdentifier = transactionIdentifier,
          readerIdentifier = readerIdentifier,
          endpoint = endpoint,
          endpointEKeypair = endpointEphemeralKeyPair,
          readerEpk = readerEPk,
          flag = flag,
          secureChannelState = SecureChannelState(),
          protocolVersion = protocolVersion,
        )
      )

      return Auth0Response(endpointEphemeralKeyPair.public, null)
    }

    log.logDebug("Processing as a Fast transaction")

    val readerGroup = context.database.findReaderGroup(readerIdentifier.groupIdentifier) ?: run {
      log.logDebug("Using dummy reader")
      context.database.dummyReaderGroup()
    }

    log.logDebug("database status: ${context.database.debug()}")
    val kPersistent = context.database.findPersistentKey(readerIdentifier) ?: run {
      log.logDebug("Using dummy persistent key")
      context.database.dummyPersistentKey()
    }

    log.logDebug("Reader $readerGroup")

    val (cryptogram, keys) = computeDerivedKeys(
      crypto = context.crypto,
      transactionIdentifier = transactionIdentifier,
      endpointPublicKey = endpoint.endpointKeypair.public,
      readerPublicKey = readerGroup.readerPublicKey,
      readerIdentifier = readerIdentifier,
      kPersistent = kPersistent,
      protocolVersion = protocolVersion,
      supportedVersions = context.versions.supportedVersions,
      readerEPk = readerEPk,
      endpointEPk = endpointEphemeralKeyPair.public,
      parameter1 = parameter1,
      transactionCode = transactionCode.code
    )
    context.transaction.moveToState(
      Auth0FastDone(
        readerEpk = readerEPk,
        readerIdentifier = readerIdentifier,
        secureChannelState = SecureChannelState(keys = keys),
        endpoint = endpoint,
        endpointEKeypair = endpointEphemeralKeyPair,
        transactionIdentifier = transactionIdentifier,
        flag = flag,
        protocolVersion = protocolVersion,
      )
    )

    log.logDebug("Cryptogram: $cryptogram")

    return Auth0Response(endpointEphemeralKeyPair.public, cryptogram)
  }

  override fun toString() =
    "Auth0Command(isFastTransaction=$isFastTransaction, transactionCode=$transactionCode, " +
      "protocolVersion=$protocolVersion, readerEPk=$readerEPk, readerId=$readerIdentifier, " +
      "transactionId=$transactionIdentifier)"

  override fun hashCode() = Objects.hash(
    isFastTransaction,
    transactionCode,
    protocolVersion,
    readerEPk,
    readerIdentifier,
    transactionIdentifier,
  )

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Auth0Command) return false

    if (isFastTransaction != other.isFastTransaction) return false
    if (transactionCode != other.transactionCode) return false
    if (protocolVersion != other.protocolVersion) return false
    if (readerEPk != other.readerEPk) return false
    if (readerIdentifier != other.readerIdentifier) return false

    return transactionIdentifier == other.transactionIdentifier
  }

  companion object {
    private const val TAG_COMMAND_PARAMETERS = 0x41
    private const val TAG_TRANSACTION_CODE = 0x42
    private const val TAG_PROTOCOL_VERSION = 0x5C
    private const val TAG_READER_EPK = 0x87
    private const val TAG_TRANSACTION_IDENTIFIER = 0x4C
    private const val TAG_READER_IDENTIFIER = 0x4D

    /**
     * Compute the cryptogram and derived keys using the HKDF.
     */
    internal fun computeDerivedKeys(
      crypto: AliroCrypto,
      transactionIdentifier: AliroIdentifier,
      endpointPublicKey: PublicKey,
      readerPublicKey: PublicKey,
      readerIdentifier: ReaderIdentifier,
      kPersistent: FixedByteArray,
      protocolVersion: Int,
      supportedVersions: ByteArray,
      readerEPk: PublicKey,
      endpointEPk: PublicKey,
      parameter1: Byte,
      transactionCode: Byte,
    ): Pair<Cryptogram, SecureChannelKeys> {
      val baos = ByteArrayOutputStream()

      DataOutputStream(baos).apply {
        write(readerPublicKey.xByteArray)
        write("VolatileFast".encodeToByteArray())
        write(readerIdentifier.toBytes())
        write(endpointPublicKey.xByteArray)

        writeByte(0x5E) // interface byte; 0x5E is for contactless interfaces
        writeByte(0x5C) // unknown function
        writeByte(supportedVersions.size)
        write(supportedVersions)
        writeByte(0x5C)
        writeByte(0x02) // length of below
        write(VersionsImpl.toByteArray(protocolVersion))
        write(readerEPk.xByteArray)
        write(transactionIdentifier.toBytes())
        write(byteArrayOf(parameter1, transactionCode)) // flag
      }

      val salt = baos.toByteArray()
      val info = endpointEPk.xByteArray

      val keyMatter = crypto.keyDerivation(kPersistent.bytes, salt, info, 144)

      return Pair(
        Cryptogram(keyMatter.sliceArray(0 until 16)),
        SecureChannelKeys(
          exchangeSkReader = SecretKeySpec(keyMatter.sliceArray(16 until 48), "AES"),
          exchangeSkDevice = SecretKeySpec(keyMatter.sliceArray(48 until 80), "AES"),
          bleSk = SecretKeySpec(keyMatter.sliceArray(80 until 112), "AES"),
          urSk = SecretKeySpec(keyMatter.sliceArray(112 until 144), "AES"),
          stepUpSk = null,
        )
      )
    }

    private fun toTlv(
      isFastTransaction: Boolean,
      transactionCode: Byte,
      protocolVersion: Int,
      readerEPk: PublicKey,
      transactionIdentifier: AliroIdentifier,
      readerIdentifier: ReaderIdentifier,
    ) = BerTlvBuilder().apply {
      addByte(BerTag(TAG_COMMAND_PARAMETERS), if (isFastTransaction) 0x01 else 0x00)
      addByte(BerTag(TAG_TRANSACTION_CODE), transactionCode)
      addBytes(BerTag(TAG_PROTOCOL_VERSION), VersionsImpl.toByteArray(protocolVersion))
      addBytes(BerTag(TAG_READER_EPK), readerEPk.encodeBasic())
      addBytes(BerTag(TAG_TRANSACTION_IDENTIFIER), transactionIdentifier.toBytes())
      addBytes(BerTag(TAG_READER_IDENTIFIER), readerIdentifier.toBytes())
    }.buildArray()

    @JvmStatic
    fun parse(crypto: AliroCrypto, apdu: ApduCommand): Auth0Command {
      val tlv = BerTlvParser().parse(apdu.data)

      return Auth0Command(
        isFastTransaction = (tlv.requireTag(TAG_COMMAND_PARAMETERS).bytesValue[0] and 0x01) > 0,
        transactionCode = TransactionCode.fromCode(tlv.requireTag(TAG_TRANSACTION_CODE).bytesValue[0]),
        readerEPk = crypto.decodePublicKey(tlv.requireTag(TAG_READER_EPK).bytesValue),
        readerIdentifier = ReaderIdentifier(tlv.requireTag(TAG_READER_IDENTIFIER).bytesValue),
        transactionIdentifier = AliroIdentifier(tlv.requireTag(TAG_TRANSACTION_IDENTIFIER).bytesValue),
        protocolVersion = tlv.requireTag(TAG_PROTOCOL_VERSION).intValue
      )
    }
  }
}
