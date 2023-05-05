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

package com.google.aliro.endpoint

import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EndpointTest {
  @Test
  fun `toString contains the public key`() {
    val endpoint =
      Endpoint(keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY))

    endpoint.toString().let {
      assertTrue(it.contains("Endpoint"))
      assertTrue(it.contains("public"))
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val endpoint =
      Endpoint(keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY))

    assertEquals(
      endpoint,
      Endpoint(keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY))
    )

    assertEquals(
      endpoint.hashCode(),
      Endpoint(
        keypairFromHex(
          CommonVectors.DEVICE_PUBLIC_KEY,
          CommonVectors.DEVICE_PRIVATE_KEY
        )
      ).hashCode()
    )

    assertNotEquals(
      endpoint,
      Endpoint(keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY))
    )
  }
}
