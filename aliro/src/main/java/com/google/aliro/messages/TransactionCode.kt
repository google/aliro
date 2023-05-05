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

import java.util.Objects

sealed class TransactionCode(val code: Byte) {
  object Unlock : TransactionCode(TRANSACTION_CODE_UNLOCK)
  object Lock : TransactionCode(TRANSACTION_CODE_LOCK)
  object Disarm : TransactionCode(TRANSACTION_CODE_DISARM)
  object ForceUserAuthentication : TransactionCode(TRANSACTION_CODE_FORCE_USER_AUTH)
  class Other(code: Byte) : TransactionCode(code)

  override fun hashCode() = Objects.hash(code)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is TransactionCode) return false

    return code == other.code
  }

  companion object {
    fun fromCode(code: Byte): TransactionCode = when (code) {
      TRANSACTION_CODE_UNLOCK -> Unlock
      TRANSACTION_CODE_LOCK -> Lock
      TRANSACTION_CODE_DISARM -> Disarm
      TRANSACTION_CODE_FORCE_USER_AUTH -> ForceUserAuthentication
      else -> Other(code)
    }

    private const val TRANSACTION_CODE_UNLOCK = 0x01.toByte()
    private const val TRANSACTION_CODE_LOCK = 0x02.toByte()
    private const val TRANSACTION_CODE_DISARM = 0x03.toByte()
    private const val TRANSACTION_CODE_FORCE_USER_AUTH = 0xEF.toByte()
  }
}