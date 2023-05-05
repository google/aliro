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

import com.google.aliro.core.AliroSerializable
import com.google.aliro.endpoint.AliroUserDeviceContext

/**
 * An Aliro command from the reader to the user device.
 */
sealed interface AliroCommand : AliroSerializable {
  /**
   * Process the command and generate a response to be sent to the reader.
   */
  fun process(context: AliroUserDeviceContext): AliroResponse
}
