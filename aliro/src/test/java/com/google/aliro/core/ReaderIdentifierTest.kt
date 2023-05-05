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
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ReaderIdentifierTest {
  @Test
  fun `reader identifiers are serialized into two groups of 16 bytes`() {
    val identifier = ReaderIdentifier(
      AliroIdentifier(HexUtil.parseHex(GROUP_ID)),
      AliroIdentifier(HexUtil.parseHex(GROUP_SUB_ID))
    )

    assertArrayEquals(HexUtil.parseHex(GROUP_ID + GROUP_SUB_ID), identifier.toBytes())
  }

  @Test
  fun `reader identifiers can be deserialized from 32 byte string`() {
    val identifier = ReaderIdentifier(HexUtil.parseHex(GROUP_ID + GROUP_SUB_ID))

    assertArrayEquals(HexUtil.parseHex(GROUP_ID), identifier.groupIdentifier.toBytes())
    assertArrayEquals(HexUtil.parseHex(GROUP_SUB_ID), identifier.groupSubIdentifier.toBytes())
  }

  companion object {
    const val GROUP_ID = "a88a7c98f28a53509ef393e5518c3af2"
    const val GROUP_SUB_ID = "11480ca80af1ffa8d3846beb99a6d1ba"
  }
}