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

package com.google.aliro.tlv

import com.payneteasy.tlv.BerTlvParser
import com.payneteasy.tlv.HexUtil
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class TlvUtilsKtTest {
  @Test
  fun `BerTlvs requireTag requires a tag to be present`() {
    val tlvs = BerTlvParser().parse(HexUtil.parseHex(TLV_DATA))

    assertNotNull(tlvs.requireTag(PRESENT_TAG_02))

    assertThrows(IllegalArgumentException::class.java) {
      tlvs.requireTag(MISSING_TAG)
    }
  }

  @Test
  fun `BerTlvs optionalTag does not require a tag to be present`() {
    val tlvs = BerTlvParser().parse(HexUtil.parseHex(TLV_DATA))

    assertNotNull(tlvs.optionalTag(PRESENT_TAG_02))
    assertNull(tlvs.optionalTag(MISSING_TAG))
  }

  @Test
  fun `BerTlv requireTag requires a tag to be present`() {
    val tlv = BerTlvParser().parse(HexUtil.parseHex(TLV_DATA)).list[0]

    assertNotNull(tlv.requireTag(PRESENT_TAG_01))

    assertThrows(IllegalArgumentException::class.java) {
      tlv.requireTag(MISSING_TAG)
    }
  }

  @Test
  fun `BerTlv optionalTag does not require a tag to be present`() {
    val tlv = BerTlvParser().parse(HexUtil.parseHex(TLV_DATA)).list[0]

    assertNotNull(tlv.optionalTag(PRESENT_TAG_01))
    assertNull(tlv.optionalTag(MISSING_TAG))
  }

  companion object {
    const val TLV_DATA = "420A74686520616E7377657243096861696C2045726973"
    const val PRESENT_TAG_01 = 0x42
    const val PRESENT_TAG_02 = 0x43
    const val MISSING_TAG = 0x13
  }
}