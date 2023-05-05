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

package com.google.aliro.crypto

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.SecureChannelState
import com.google.crypto.tink.subtle.EllipticCurves
import com.google.crypto.tink.subtle.EllipticCurves.ecdsaDer2Ieee
import com.google.crypto.tink.subtle.EllipticCurves.ecdsaIeee2Der
import com.google.crypto.tink.subtle.Hkdf
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec

abstract class JvmCommonCrypto : AliroCrypto {
  private val random = SecureRandom()

  override fun randomBytes(count: Int): ByteArray {
    val buffer = ByteArray(count)
    random.nextBytes(buffer)

    return buffer
  }

  override fun decodePublicKey(encoded: ByteArray): PublicKey {
    val factory = KeyFactory.getInstance(KEYPAIR_ALGORITHM)
    val point = EllipticCurves.pointDecode(
      EllipticCurves.CurveType.NIST_P256,
      EllipticCurves.PointFormatType.UNCOMPRESSED,
      encoded
    )
    return factory.generatePublic(ECPublicKeySpec(point, EllipticCurves.getNistP256Params()))
  }

  override fun keyDerivation(
    inputKeyingMaterial: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputSize: Int,
  ): ByteArray =
    Hkdf.computeHkdf(KEY_ALGORITHM_HMAC_SHA256, inputKeyingMaterial, salt, info, outputSize)

  override fun generateEphemeralKeypair(): KeyPair {
    val generator = KeyPairGenerator.getInstance(KEYPAIR_ALGORITHM).apply {
      initialize(KEYPAIR_PARAMETER_SPEC)
    }

    return generator.generateKeyPair()
  }

  override fun generateSignature(data: ByteArray, privateKey: PrivateKey): ByteArray =
    ecdsaDer2Ieee(Signature.getInstance(SIGNATURE_ALGORITHM).apply {
      initSign(privateKey)
      update(data)
    }.sign(), SIGNATURE_SIZE)

  override fun verifySignature(
    data: ByteArray,
    publicKey: PublicKey,
    signature: ByteArray,
  ): Boolean =
    Signature.getInstance(SIGNATURE_ALGORITHM).apply {
      initVerify(publicKey)
      update(data)
    }.verify(ecdsaIeee2Der(signature))

  override fun diffieHellmanKeyDerivation(
    remotePublicKey: PublicKey,
    secretKey: PrivateKey,
    transactionIdentifier: AliroIdentifier,
  ): ByteArray {
    val sharedSecretPoint = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM).apply {
      init(secretKey)
      doPhase(remotePublicKey, true)
    }.generateSecret()

    // BSI TR-03111 section 4.3 based on ANSI X9.63
    return MessageDigest.getInstance("sha256").digest(
      sharedSecretPoint
        + byteArrayOf(0x00, 0x00, 0x00, 0x01) // counter when generating larger keys
        + transactionIdentifier.identifier.bytes // SharedInfo
    )
  }

  override fun responseEncryption(
    channelState: SecureChannelState,
    data: ByteArray,
  ): Pair<SecureChannelState, ByteArray> {
    channelState.keys?.let { keys ->
      val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM).apply {
        init(
          Cipher.ENCRYPT_MODE, keys.exchangeSkDevice,
          GCMParameterSpec(
            GCM_AUTHENTICATION_TAG_SIZE,
            GCM_DEVICE_IV_PREFIX + byteArrayOf(
              0x00, 0x00, 0x00, channelState.counter.toByte()
            )
          )
        )
      }

      val ciphertext = cipher.doFinal(data)

      return Pair(channelState.copy(counter = channelState.counter + 1), ciphertext)

    } ?: throw IllegalArgumentException("Missing channel keys")
  }

  override fun responseDecryption(
    channelState: SecureChannelState,
    ciphertext: ByteArray,
  ): Pair<SecureChannelState, ByteArray> {
    channelState.keys?.let { keys ->
      val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM).apply {
        init(
          Cipher.DECRYPT_MODE, keys.exchangeSkDevice,
          GCMParameterSpec(
            GCM_AUTHENTICATION_TAG_SIZE,
            GCM_DEVICE_IV_PREFIX + byteArrayOf(
              0x00, 0x00, 0x00, channelState.counter.toByte()
            )
          )
        )
      }

      val plaintext = cipher.doFinal(ciphertext)

      return Pair(channelState.copy(counter = channelState.counter + 1), plaintext)

    } ?: throw IllegalArgumentException("Missing channel keys")
  }

  companion object {
    const val KEYPAIR_ALGORITHM = "EC"
    const val EC_PARAMETER_SPEC = "secp256r1"
    const val KEY_ALGORITHM_HMAC_SHA256 = "HMACSHA256"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    const val KEY_AGREEMENT_ALGORITHM = "ECDH"
    const val ENCRYPTION_ALGORITHM = "Aes/Gcm/NoPadding"
    const val SIGNATURE_SIZE = 64
    const val GCM_AUTHENTICATION_TAG_SIZE = 128
    private val GCM_DEVICE_IV_PREFIX = byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)

    internal val KEYPAIR_PARAMETER_SPEC: ECParameterSpec = EllipticCurves.getNistP256Params()
  }
}
