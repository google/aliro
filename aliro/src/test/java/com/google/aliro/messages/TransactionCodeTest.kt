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

import com.google.aliro.core.b
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class TransactionCodeTest {
  @Test
  fun `fromCode will handle the known code types`() {
    assertEquals(TransactionCode.Unlock, TransactionCode.fromCode(b(0x01)))
    assertEquals(TransactionCode.Lock, TransactionCode.fromCode(b(0x02)))
    assertEquals(TransactionCode.Disarm, TransactionCode.fromCode(b(0x03)))
    assertEquals(TransactionCode.ForceUserAuthentication, TransactionCode.fromCode(b(0xEF)))
    assertEquals(TransactionCode.Other(0x42), TransactionCode.fromCode(b(0x42)))
  }

  @Test
  fun `equals and hashCode function as expected`() {
    assertEquals(TransactionCode.Other(0x42), TransactionCode.Other(0x42))
    assertEquals(TransactionCode.Other(0x42).hashCode(), TransactionCode.Other(0x42).hashCode())
    assertNotEquals(TransactionCode.Other(0x23), TransactionCode.Other(0x42))
  }
}