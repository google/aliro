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

/**
 * An in-memory store of transaction state.
 */
class Transaction(private val logger: AliroLogger) {
  /**
   * The current transaction. [Initial] if there is no active transaction.
   */
  internal var state: TransactionState = Initial
    private set

  /**
   * Valid state transitions. Any transitions attempted outside of this set will throw exceptions.
   */
  private val validTransitions = setOf(
    Initial::class to SelectDone::class,

    SelectDone::class to Initial::class,
    SelectDone::class to Auth0FastDone::class,
    SelectDone::class to Auth0StandardDone::class,

    Auth0FastDone::class to Initial::class,
    Auth0FastDone::class to SelectDone::class,
    Auth0FastDone::class to Auth1Done::class,

    Auth0StandardDone::class to Initial::class,
    Auth0StandardDone::class to Auth1Done::class,

    Auth1Done::class to Initial::class,
    Auth1Done::class to SelectDone::class,
  )

  /**
   * Move the transaction to the new state.
   */
  internal fun moveToState(newState: TransactionState) {
    logger.logDebug("Transaction: moveToState: $newState")

    // Allow identity state updates, so updates are permitted and stop() can be called twice.
    if (state::class == newState::class || validTransitions.contains(state::class to newState::class)) {
      state = newState
    } else {
      throw IllegalStateException("Cannot transition from ${state::class.simpleName} state to ${newState::class.simpleName} state")
    }
  }

  /**
   * Resets the transaction to the initial, empty state.
   */
  fun stop() {
    logger.logDebug("Transaction: stop")
    state = Initial
  }
}
