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
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey


/**
 * A collection of cryptographic routines for Aliro.
 */
interface AliroCrypto {
  /**
   * Generate [count] cryptographically-secure random bytes.
   */
  fun randomBytes(count: Int): ByteArray

  /**
   * Generate or retrieve a keypair with the given [alias].
   */
  fun generateOrRetrieveKeypair(alias: String): KeyPair

  /**
   * Generate a keypair that will not be persisted beyond a single transaction.
   */
  fun generateEphemeralKeypair(): KeyPair

  /**
   * An implementation of the HKDF. This creates a [ByteArray] of [outputSize] bytes.
   */
  fun keyDerivation(
    inputKeyingMaterial: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputSize: Int,
  ): ByteArray

  /**
   * Decode the [encoded] public key, according to Aliro specification encoding rules.
   */
  fun decodePublicKey(encoded: ByteArray): PublicKey

  /**
   * Generate Transaction Data.
   */
  fun generateSignature(data: ByteArray, privateKey: PrivateKey): ByteArray

  /**
   * Verifies the [signature] of [data] using the given [publicKey].
   */
  fun verifySignature(data: ByteArray, publicKey: PublicKey, signature: ByteArray): Boolean

  /**
   * Compute a key using Diffie-Hellman and BSI TR-03111 using the given ephemeral public/private
   * keys and [transactionIdentifier].
   */
  fun diffieHellmanKeyDerivation(
    remotePublicKey: PublicKey,
    secretKey: PrivateKey,
    transactionIdentifier: AliroIdentifier,
  ): ByteArray

  fun responseEncryption(
    channelState: SecureChannelState,
    data: ByteArray,
  ): Pair<SecureChannelState, ByteArray>

  fun responseDecryption(
    channelState: SecureChannelState,
    ciphertext: ByteArray,
  ): Pair<SecureChannelState, ByteArray>
}
