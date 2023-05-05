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

package com.google.aliro.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/**
 * A complete crypto implementation suitable only for tests, as it does not persist
 * any long-term keys.
 */
internal class JvmCryptoImpl : JvmCommonCrypto() {
  override fun generateOrRetrieveKeypair(alias: String): KeyPair {
    val generator = KeyPairGenerator.getInstance(KEYPAIR_ALGORITHM).apply {
      initialize(ECGenParameterSpec(EC_PARAMETER_SPEC))
    }

    return generator.generateKeyPair()
  }
}
