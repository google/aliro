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

package com.google.aliro.reader

import com.google.aliro.VersionsImpl
import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroErrorCode
import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.SecureChannelKeys
import com.google.aliro.core.SecureChannelState
import com.google.aliro.core.toHex
import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.messages.AliroCommand
import com.google.aliro.messages.AliroResponse
import com.google.aliro.messages.Auth0Command
import com.google.aliro.messages.Auth0Response
import com.google.aliro.messages.Auth1Command
import com.google.aliro.messages.Auth1Response
import com.google.aliro.messages.ControlFlowCommand
import com.google.aliro.messages.ControlFlowResponse
import com.google.aliro.messages.ENDPOINT_USAGE
import com.google.aliro.messages.READER_USAGE
import com.google.aliro.messages.ReaderSignature
import com.google.aliro.messages.SelectCommand
import com.google.aliro.messages.SelectResponse
import com.google.aliro.messages.TransactionCode
import com.google.aliro.messages.auth1Info
import com.google.aliro.messages.generateAuthenticationData
import com.google.aliro.messages.generateAuthenticationSignature
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.util.Objects
import javax.crypto.spec.SecretKeySpec

/**
 * An Aliro reader implementation.
 */
class AliroReader(
  private val context: AliroReaderContext,
  /**
   * An APDU-level transceiver.
   */
  private val transceiver: suspend (ByteArray) -> ByteArray,
) {

  /**
   * Execute a complete Aliro transaction.
   */
  suspend fun transact(action: TransactionCode): TransactionResult {
    val log = context.logger
    log.logDebug("Starting transaction...")
    val supportedVersions = sendSelect() ?: return TransactionResult.Unauthorized

    val protocolVersion = VersionsImpl.highestSupportedVersion(supportedVersions)
      ?: throw AliroError(AliroErrorCode.GENERIC_ERROR, "No supported versions found")

    log.logDebug("Selected Aliro")

    val readerEKeypair = context.crypto.generateEphemeralKeypair()
    log.logDebug("Generated reader ephemeral pk: ${readerEKeypair.public}")

    val transactionId = AliroIdentifier.randomIdentifier(context.crypto)
    log.logDebug("Created new transaction ID: $transactionId")

    return when (val auth0Result = sendAuth0(
      readerEKeypair = readerEKeypair,
      transactionId = transactionId,
      protocolVersion = protocolVersion,
      supportedVersions = supportedVersions,
      action = action
    )) {
      is Authorized -> {
        sendControlFlow(true)
        log.logDebug("Auth0 result: Authorized")
        TransactionResult.Authorized(transactionId, auth0Result.endpointPk as ECPublicKey)
      }

      is NeedAuth1 -> return sendAuth1(auth0Result)
    }
  }

  private suspend fun transceive(command: AliroCommand): ApduResponse {
    val sending = command.toBytes()
    context.logger.logDebug("Send: ${HexUtil.toHexString(sending)}")
    val resultRaw = transceiver(sending)
    context.logger.logDebug("Response: ${HexUtil.toHexString(resultRaw)}")

    return ApduResponse.parse(resultRaw)
  }

  sealed class TransactionResult {
    class Authorized(
      val transactionId: AliroIdentifier,
      val endpointPublicKey: ECPublicKey
    ) : TransactionResult() {
      override fun toString() = "Authorized(transactionId=$transactionId, endpointPublicKey=$endpointPublicKey)"
    }

    object Unauthorized : TransactionResult()
  }

  internal suspend fun sendSelect(): ByteArray? {
    context.logger.logDebug("Sending SELECT")

    val select = SelectCommand(SelectCommand.AID)
    val response = transceive(select)

    if (!response.isSuccessful) {
      context.logger.logError("SELECT not successful")

      return null
    }

    val selectResponse = SelectResponse.parse(response)

    return selectResponse.supportedVersions
  }

  internal suspend fun sendControlFlow(success: Boolean) {
    context.logger.logDebug("Sending CONTROL FLOW: success=$success")
    val response = ControlFlowResponse.parse(transceive(ControlFlowCommand(success)))
    context.logger.logDebug("Response: $response")
  }

  internal suspend fun sendAuth0(
    readerEKeypair: KeyPair,
    transactionId: AliroIdentifier,
    protocolVersion: Int,
    supportedVersions: ByteArray,
    action: TransactionCode
  ): Auth0Result {
    val log = context.logger
    log.logDebug("Sending AUTH0")

    val auth0Command = Auth0Command(
      isFastTransaction = context.readerConfiguration.shouldSendFastTransaction,
      transactionCode = action,
      protocolVersion = protocolVersion,
      readerEPk = readerEKeypair.public,
      readerIdentifier = context.readerConfiguration.identifier,
      transactionIdentifier = transactionId,
    )

    val response = Auth0Response.parse(
      aliroContext = context,
      apduResponse = transceive(auth0Command),
    )

    // fast transaction
    response.cryptogram?.let { deviceCryptogram ->
      val endpointPk = checkCryptograms(
        transactionId = transactionId,
        protocolVersion = protocolVersion,
        supportedVersions = supportedVersions,
        readerEPk = readerEKeypair.public,
        endpointEPk = response.endpointEPk,
        parameter1 = auth0Command.parameter1,
        transactionCode = auth0Command.transactionCode,
        deviceCryptogram = deviceCryptogram
      )
      if (endpointPk != null) {
        return Authorized(endpointPk = endpointPk)
      }
    }

    log.logDebug("No cryptograms match. Proceeding to AUTH1")

    return NeedAuth1(
      protocolVersion = protocolVersion,
      readerEKeypair = readerEKeypair,
      endpointEPk = response.endpointEPk,
      transactionIdentifier = transactionId,
      flag = FixedByteArray(
        byteArrayOf(auth0Command.parameter1, auth0Command.transactionCode.code)
      ),
      supportedVersions = supportedVersions,
    )
  }

  internal fun checkCryptograms(
    transactionId: AliroIdentifier,
    protocolVersion: Int,
    supportedVersions: ByteArray,
    readerEPk: PublicKey,
    endpointEPk: PublicKey,
    parameter1: Byte,
    transactionCode: TransactionCode,
    deviceCryptogram: Cryptogram
  ): PublicKey? {
    context.knownUserDevices.forEach { knownDevice ->
      context.logger.logDebug(
        "Checking cryptogram of known device with public key ${
          HexUtil.toHexString(knownDevice.publicKey.encodeBasic())
        }"
      )
      val (cryptogram, _) = Auth0Command.computeDerivedKeys(
        crypto = context.crypto,
        transactionIdentifier = transactionId,
        endpointPublicKey = knownDevice.publicKey,
        readerPublicKey = context.readerConfiguration.keypair.public,
        readerIdentifier = context.readerConfiguration.identifier,
        kPersistent = knownDevice.kPersistent,
        protocolVersion = protocolVersion,
        supportedVersions = supportedVersions,
        readerEPk = readerEPk,
        endpointEPk = endpointEPk,
        parameter1 = parameter1,
        transactionCode = transactionCode.code,
      )

      if (deviceCryptogram == cryptogram) {
        context.logger.logDebug("The cryptograms match!")
        context.logger.logDebug("User device has a public key of: ${HexUtil.toHexString(knownDevice.publicKey.encodeBasic())}")
        // at this point the user device is known
        return knownDevice.publicKey
      }
    }
    return null
  }

  private suspend fun sendAuth1(auth0Result: NeedAuth1): TransactionResult {
    val log = context.logger
    val readerEpk = auth0Result.readerEKeypair.public
    val endpointEPk = auth0Result.endpointEPk
    val transactionIdentifier = auth0Result.transactionIdentifier

    val signature = generateAuthenticationSignature(
      crypto = context.crypto,
      signingPrivateKey = context.readerConfiguration.keypair.private,
      readerIdentifier = context.readerConfiguration.identifier,
      readerEPublicKey = readerEpk,
      endpointEPublicKey = endpointEPk,
      transactionIdentifier = transactionIdentifier,
      usage = READER_USAGE,
    )
    val auth1 = Auth1Command(true, ReaderSignature(signature))

    val response = Auth1Response.parse(transceive(auth1))

    val kDh = context.crypto.diffieHellmanKeyDerivation(
      remotePublicKey = auth0Result.endpointEPk,
      secretKey = auth0Result.readerEKeypair.private,
      transactionIdentifier = auth0Result.transactionIdentifier,
    )

    val versionBytes = VersionsImpl.toByteArray(auth0Result.protocolVersion)
    log.logDebug("Diffie Hellman key: ${HexUtil.toFormattedHexString(kDh)}")


    val derivedKeys = context.crypto.keyDerivation(
      inputKeyingMaterial = kDh,
      info = auth1Info(
        readerEPk = readerEpk,
        endpointEPk = endpointEPk,
        transactionIdentifier = transactionIdentifier,
        flag = auth0Result.flag,
        versionBytes = versionBytes,
        type = Auth1Command.KEY_DERIVATION_TYPE_VOLATILE,
        supportedVersions = auth0Result.supportedVersions,
      ),
      salt = ByteArray(32),
      outputSize = 160,
    )
    val keys = SecureChannelKeys(
      exchangeSkReader = SecretKeySpec(derivedKeys.sliceArray(0 until 32), "AES"),
      exchangeSkDevice = SecretKeySpec(derivedKeys.sliceArray(32 until 64), "AES"),
      stepUpSk = SecretKeySpec(derivedKeys.sliceArray(64 until 96), "AES"),
      bleSk = SecretKeySpec(derivedKeys.sliceArray(96 until 128), "AES"),
      urSk = SecretKeySpec(derivedKeys.sliceArray(128 until 160), "AES"),
    )

    val keyMaterial = context.crypto.keyDerivation(
      inputKeyingMaterial = kDh,
      info = auth1Info(
        readerEPk = readerEpk,
        endpointEPk = endpointEPk,
        transactionIdentifier = transactionIdentifier,
        flag = auth0Result.flag,
        versionBytes = versionBytes,
        type = Auth1Command.KEY_DERIVATION_TYPE_PERSISTENT,
        supportedVersions = auth0Result.supportedVersions,
      ),
      salt = ByteArray(32),
      outputSize = 32,
    )
    val kPersistent = keyMaterial.slice(0 until 32).toByteArray()

    if (response.sw1 == AliroResponse.SW1_NO_FURTHER_QUALIFICATION) {
      val responseDecrypted = response.decrypt(context, SecureChannelState(keys = keys))

      log.logDebug("Decrypted response: $responseDecrypted")

      responseDecrypted.endpointPk?.let { endpointPk ->
        val data = generateAuthenticationData(
          readerIdentifier = context.readerConfiguration.identifier,
          readerEPublicKey = readerEpk,
          endpointEPublicKey = endpointEPk,
          transactionIdentifier = transactionIdentifier,
          usage = ENDPOINT_USAGE,
        )
        val verified = context.crypto.verifySignature(
          data = data,
          publicKey = endpointPk,
          signature = responseDecrypted.endpointSignature.bytes
        )

        if (verified) {
          log.logDebug("Endpoint signature verified!")
          val knownDevice = KnownUserDevice(
            publicKey = endpointPk,
            kPersistent = FixedByteArray(kPersistent),
          )
          context.knownUserDevices.add(knownDevice)
          log.logDebug("Adding known user device: $knownDevice")

          return TransactionResult.Authorized(transactionIdentifier, endpointPk as ECPublicKey)
        } else {
          log.logError("Endpoint signature NOT verified :-(")
        }
      }
    }

    return TransactionResult.Unauthorized
  }
}

internal sealed interface Auth0Result

internal class Authorized(val endpointPk: PublicKey) : Auth0Result

internal class NeedAuth1(
  val protocolVersion: Int,
  val supportedVersions: ByteArray,
  val readerEKeypair: KeyPair,
  val endpointEPk: PublicKey,
  val transactionIdentifier: AliroIdentifier,
  val flag: FixedByteArray,
) : Auth0Result {

  override fun hashCode() = Objects.hash(
    protocolVersion,
    supportedVersions.contentHashCode(),
    readerEKeypair.public,
    endpointEPk,
    transactionIdentifier,
    flag,
  )

  override fun toString() =
    "NeedAuth1(protocolVersion=$protocolVersion, supportedVersions=${supportedVersions.toHex()}, readerEKeypair=(public=${readerEKeypair.public}, private=<redacted>), endpointEPk=$endpointEPk, transactionId=$transactionIdentifier, flag=$flag)"

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is NeedAuth1) return false

    if (protocolVersion != other.protocolVersion) return false
    if (!supportedVersions.contentEquals(other.supportedVersions)) return false
    // does not compare private keys
    if (readerEKeypair.public != other.readerEKeypair.public) return false
    if (endpointEPk != other.endpointEPk) return false
    if (transactionIdentifier != other.transactionIdentifier) return false
    return flag == other.flag
  }
}
