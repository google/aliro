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

import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class TransactionTest {
  private val logger = mockk<AliroLogger>(relaxed = true)
  private val transaction = Transaction(logger)

  @Test
  fun `the state property is Initial when there is no transaction`() {
    assertEquals(Initial, transaction.state)
  }

  @Test
  fun `moveToState moves to a new state`() {
    assertEquals(Initial, transaction.state)

    transaction.moveToState(SelectDone)

    assertEquals(SelectDone, transaction.state)

    val auth0StandardDone = mockk<Auth0StandardDone>()
    transaction.moveToState(auth0StandardDone)
    assertEquals(auth0StandardDone, transaction.state)
  }

  @Test
  fun `moveToState checks valid state transitions`() {
    assertEquals(Initial, transaction.state)

    assertThrows(IllegalStateException::class.java) {
      transaction.moveToState(mockk<Auth0Done>())
    }

    assertThrows(IllegalStateException::class.java) {
      transaction.moveToState(mockk<Auth1Done>())
    }

    assertEquals(Initial, transaction.state)

    transaction.moveToState(SelectDone)

    assertThrows(IllegalStateException::class.java) {
      transaction.moveToState(mockk<Auth1Done>())
    }

    assertEquals(SelectDone, transaction.state)
  }

  @Test
  fun `stop clears the current transaction`() {
    transaction.moveToState(SelectDone)

    transaction.stop()

    assertEquals(Initial, transaction.state)
  }
}
