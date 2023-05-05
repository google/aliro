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

import com.google.aliro.VersionsImpl
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Initial
import com.google.aliro.crypto.AliroCrypto
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AliroContextImplTest {
  private val crypto = mockk<AliroCrypto>()
  private val db = mockk<UserDeviceDatabase>()
  private val logger = mockk<AliroLogger>()

  @Test
  fun `AliroContextImpl is a basic data object`() {
    val context = AliroContextImpl(crypto, db, logger)

    assertEquals(crypto, context.crypto)
    assertEquals(db, context.database)
    assertEquals(logger, context.logger)
    assertTrue(context.versions is VersionsImpl)
    assertTrue(context.transaction.state is Initial)
  }
}
