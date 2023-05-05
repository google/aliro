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

import com.google.aliro.core.AliroLogger
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.endpoint.AliroContext

/**
 * The resources necessary for an Aliro reader.
 */
interface AliroReaderContext : AliroContext {
  /**
   * A palette of Aliro cryptography functions.
   */
  val readerConfiguration: ReaderConfiguration
  val knownUserDevices: MutableList<KnownUserDevice>
}

/**
 * A simple concrete implementation of the context.
 */
class AliroReaderContextImpl(
  override val crypto: AliroCrypto,
  override val readerConfiguration: ReaderConfiguration,
  override val knownUserDevices: MutableList<KnownUserDevice>,
  override val logger: AliroLogger,
) : AliroReaderContext
