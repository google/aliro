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

import com.payneteasy.tlv.HexUtil

/**
 * An Aliro-specific error that contains an [AliroErrorCode] and a human-readable reason.
 */
class AliroError(val aliroErrorCode: AliroErrorCode, reason: String) :
  Exception("$aliroErrorCode: $reason")

enum class AliroErrorCode(val status: Int) {
  GENERIC_ERROR(0x6400),
  MEMORY_FAILURE(0x6581),
  WRONG_LC_LENGTH(0x6700),
  LOGICAL_CHANNEL_NOT_SUPPORTED(0x6881),
  SECURITY_STATUS_NOT_SATISFIED(0x6982),
  CONDITIONS_OF_USE_NOT_SATISFIED(0x6985),
  INCORRECT_P1_P2(0x6b00),
  INVALID_INSTRUCTION(0x6d00),
  INVALID_CLASS(0x6e00),
  NO_PRECISE_DIAGNOSIS(0x6f00);

  /**
   * The most significant byte of the error status code.
   */
  val sw1: Byte
    get() = b(status.shr(8) and 0xff)

  /**
   * The least significant byte of the error status code.
   */
  val sw2: Byte
    get() = b(status and 0xff)

  override fun toString() = "AliroErrorCode ${HexUtil.toHexString(status.to2ByteArray())}"
}