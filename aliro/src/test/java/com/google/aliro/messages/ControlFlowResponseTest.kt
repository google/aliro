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

import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ControlFlowResponseTest {

  @Test
  fun `serializing the ControlFlowResponse outputs correct bytes`() {
    assertArrayEquals(HexUtil.parseHex(RESPONSE_ACK), ControlFlowResponse().toBytes())
  }

  @Test
  fun `parse will create a proper object`() {
    assertEquals(
      ControlFlowResponse(),
      ControlFlowResponse.parse(ApduResponse.parse(HexUtil.parseHex(RESPONSE_ACK)))
    )
  }

  @Test
  fun `round tripping works with any response code`() {
    val expected = ControlFlowResponse(0x9142)

    assertEquals(
      expected,
      ControlFlowResponse.parse(ApduResponse.parse(expected.toBytes()))
    )
  }

  @Test
  fun `toString includes useful information`() {
    val response = ControlFlowResponse(0x9142)

    response.toString().let {
      assertTrue(it.contains("ControlFlowResponse"))
      assertTrue(it.contains(RESPONSE_OTHER))
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val response = ControlFlowResponse(0x9142)

    assertEquals(response, ControlFlowResponse(0x9142))
    assertEquals(response.hashCode(), ControlFlowResponse(0x9142).hashCode())

    assertNotEquals(response, ControlFlowResponse(0x9000))
  }

  companion object {
    const val RESPONSE_ACK = "9000"
    const val RESPONSE_OTHER = "9142"
  }
}
