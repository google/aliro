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

package com.google.aliro.endpoint

import com.google.aliro.Versions
import com.google.aliro.VersionsImpl
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Transaction
import com.google.aliro.crypto.AliroCrypto

/**
 * A collection of all the resources necessary to process Aliro commands in order to generate
 * responses to the reader.
 */
interface AliroContext {
  /**
   * A palette of Aliro cryptography functions.
   */
  val crypto: AliroCrypto

  /**
   * An error and debugging logger.
   */
  val logger: AliroLogger
}

interface AliroUserDeviceContext : AliroContext {
  /**
   * The database of endpoints and known readers.
   */
  val database: UserDeviceDatabase

  /**
   * The source of truth for transaction state.
   */
  val transaction: Transaction

  /**
   * Protocol version information.
   */
  val versions: Versions
}

/**
 * A basic implementation of an [AliroContext] with an in-memory [transaction] state registry.
 */
class AliroContextImpl(
  override val crypto: AliroCrypto,
  override val database: UserDeviceDatabase,
  override val logger: AliroLogger,
) : AliroUserDeviceContext {
  override val transaction = Transaction(logger)
  override val versions: Versions = VersionsImpl
}
