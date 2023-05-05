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

import com.google.aliro.core.AliroSerializable


sealed interface AliroResponse : AliroSerializable {
  companion object {
    /**
     * No Further Qualification. This is the complete response.
     */
    const val SW1_NO_FURTHER_QUALIFICATION = 0x90.toByte()

    /**
     * Bytes are still available.
     */
    const val SW1_BYTES_STILL_AVAILABLE = 0x61.toByte()
  }
}
