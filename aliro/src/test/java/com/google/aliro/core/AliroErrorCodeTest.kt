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

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class AliroErrorCodeTest {

  @Test
  fun `AliroError message is as expected`() {
    assertEquals(
      "AliroErrorCode 6D00: the reason",
      AliroError(AliroErrorCode.INVALID_INSTRUCTION, "the reason").message
    )
  }

  @Test
  fun `AliroErrorCode status bytes can be read`() {
    val err = AliroErrorCode.CONDITIONS_OF_USE_NOT_SATISFIED

    assertEquals(0x6985, err.status)
    assertEquals(0x69.toByte(), err.sw1)
    assertEquals(0x85.toByte(), err.sw2)
  }
}