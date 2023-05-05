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

import com.google.aliro.core.byteAtIndex
import com.google.aliro.core.to2ByteArray
import com.google.aliro.core.toHex
import com.google.nfc.apdu.ApduResponse
import com.google.nfc.apdu.bytesToInt
import java.util.Objects

class ControlFlowResponse internal constructor(val status: Int) : AliroResponse {
  constructor() : this(0x9000)

  override fun toString() = "ControlFlowResponse(status=${status.to2ByteArray().toHex()})"

  override fun hashCode() = Objects.hash(status)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is ControlFlowResponse) return false

    return status == other.status
  }

  override fun toBytes(): ByteArray =
    ApduResponse(status.byteAtIndex(1), status.byteAtIndex(0)).serialize()


  companion object {
    @JvmStatic
    fun parse(response: ApduResponse): ControlFlowResponse {
      return ControlFlowResponse(bytesToInt(response.sw1, response.sw2))
    }
  }
}
