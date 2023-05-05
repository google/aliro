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

import com.google.aliro.core.AliroErrorCode
import com.google.nfc.apdu.ApduResponse
import java.util.Objects

class ErrorResponse(val aliroErrorCode: AliroErrorCode) : AliroResponse {
  override fun toBytes(): ByteArray {
    return ApduResponse(aliroErrorCode.sw1, aliroErrorCode.sw2).serialize()
  }

  override fun toString() = "ErrorResponse(aliroErrorCode=$aliroErrorCode)"

  override fun hashCode() = Objects.hash(aliroErrorCode)
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ErrorResponse) return false

    return aliroErrorCode == other.aliroErrorCode
  }
}
