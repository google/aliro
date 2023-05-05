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

package com.google.aliro.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.aliro.crypto.JvmCommonCrypto
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * An implementation of AliroCrypto which uses standard Java crypto for everything except for the
 * long-term keypair. The long-term keypairs are stored securely in a way that does not allow for
 * exfiltration of the private keys.
 *
 * Note that this means that a given credential is permanently bound to a specific user device,
 * so if backups or transfers of credentials are desired, a different long-term keypair technique
 * should be used.
 */
class AndroidCrypto : JvmCommonCrypto() {
  override fun generateOrRetrieveKeypair(alias: String): KeyPair {
    val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
    keystore.load(null)

    val keypair = if (keystore.containsAlias(alias)) {
      val private = keystore.getKey(alias, null) as PrivateKey
      val public = keystore.getCertificate(alias).publicKey

      KeyPair(public, private)
    } else {
      val generator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
      generator.initialize(
        KeyGenParameterSpec.Builder(
          alias,
          KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
            KeyProperties.PURPOSE_AGREE_KEY
        ).apply {
          setAlgorithmParameterSpec(ECGenParameterSpec(EC_PARAMETER_SPEC))
          setDigests(KeyProperties.DIGEST_SHA256)
          setInvalidatedByBiometricEnrollment(false)
          setUserAuthenticationRequired(false)
        }.build()
      )

      generator.generateKeyPair()
    }

    return keypair
  }

  companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
  }
}
