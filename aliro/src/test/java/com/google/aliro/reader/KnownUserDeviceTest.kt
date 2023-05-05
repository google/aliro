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

package com.google.aliro.reader

import com.google.aliro.core.FixedByteArray
import com.google.aliro.messages.CommonVectors
import com.google.aliro.messages.ExpeditedStandard
import com.google.aliro.publicKeyFromHex
import com.payneteasy.tlv.HexUtil.parseHex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.interfaces.ECPublicKey

class KnownUserDeviceTest {
  private val knownUserDevice = KnownUserDevice(
    publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
    kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
  )

  @Test
  fun `equals and hashCode function as expected`() {
    assertEquals(
      knownUserDevice,
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
      )
    )

    assertEquals(
      knownUserDevice.hashCode(),
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
      ).hashCode()
    )

    assertNotEquals(
      knownUserDevice,
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY),
        kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
      )
    )

    assertNotEquals(
      knownUserDevice,
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        kPersistent = FixedByteArray(ByteArray(32)),
      )
    )
  }

  @Test
  fun `toString contains useful information`() {
    knownUserDevice.toString().let {
      assertTrue(it.contains("KnownUserDevice"))
      assertTrue(it.contains((knownUserDevice.publicKey as ECPublicKey).w.affineX.toString()))
      assertTrue(it.contains("kPersistent=<redacted>"))
    }
  }
}