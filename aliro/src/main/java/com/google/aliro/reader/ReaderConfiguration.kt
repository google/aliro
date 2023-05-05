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

import com.google.aliro.core.ReaderIdentifier
import java.security.KeyPair
import java.util.Objects

/**
 * Configuration parameters for an Aliro reader. These should be persisted
 * across runs.
 */
class ReaderConfiguration(
  val identifier: ReaderIdentifier,
  val keypair: KeyPair,
  val shouldSendFastTransaction: Boolean = true,
) {
  override fun toString() =
    "ReaderConfiguration(ID=$identifier, keypair=${keypair.public}, shouldSendFastTransaction=$shouldSendFastTransaction)"

  override fun hashCode() =
    Objects.hash(identifier, keypair.public, shouldSendFastTransaction)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ReaderConfiguration) return false

    if (identifier != other.identifier) return false
    if (keypair.public != other.keypair.public) return false
    return shouldSendFastTransaction == other.shouldSendFastTransaction
  }
}
