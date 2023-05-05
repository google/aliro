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

package com.google.aliro.core

import com.google.aliro.endpoint.Endpoint
import java.security.KeyPair
import java.security.PublicKey
import javax.crypto.SecretKey

/**
 * An Aliro transaction state.
 */
internal sealed interface TransactionState

/**
 * Initial transaction state. The next valid state is `SelectDone`.
 */
internal object Initial : TransactionState

/**
 * The SELECT command has completed successfully.
 */
internal object SelectDone : TransactionState

internal interface AuthCommon : TransactionState {
  val transactionIdentifier: AliroIdentifier
  val readerIdentifier: ReaderIdentifier
  val endpoint: Endpoint
  val readerEpk: PublicKey
  val endpointEKeypair: KeyPair
  val flag: FixedByteArray
  val secureChannelState: SecureChannelState
  val protocolVersion: Int
}

internal interface Auth0Done : AuthCommon

data class SecureChannelKeys(
  val exchangeSkReader: SecretKey,
  val exchangeSkDevice: SecretKey,
  val bleSk: SecretKey,
  val urSk: SecretKey,
  val stepUpSk: SecretKey?,
)

data class SecureChannelState(
  val counter: Int = 1,
  val keys: SecureChannelKeys? = null,
)

/**
 * An AUTH0 fast command has completed.
 */
internal class Auth0FastDone(
  override val secureChannelState: SecureChannelState,
  override val transactionIdentifier: AliroIdentifier,
  override val endpoint: Endpoint,
  override val readerIdentifier: ReaderIdentifier,
  override val readerEpk: PublicKey,
  override val endpointEKeypair: KeyPair,
  override val flag: FixedByteArray,
  override val protocolVersion: Int,
) : Auth0Done

/**
 * An AUTH0 standard command has completed.
 */
internal class Auth0StandardDone(
  override val secureChannelState: SecureChannelState,
  override val transactionIdentifier: AliroIdentifier,
  override val endpoint: Endpoint,
  override val readerIdentifier: ReaderIdentifier,
  override val readerEpk: PublicKey,
  override val endpointEKeypair: KeyPair,
  override val flag: FixedByteArray,
  override val protocolVersion: Int,
) : Auth0Done

internal class Auth1Done(
  override val secureChannelState: SecureChannelState,
  override val transactionIdentifier: AliroIdentifier,
  override val readerEpk: PublicKey,
  override val readerIdentifier: ReaderIdentifier,
  override val endpoint: Endpoint,
  override val endpointEKeypair: KeyPair,
  override val flag: FixedByteArray,
  override val protocolVersion: Int,
) : AuthCommon
