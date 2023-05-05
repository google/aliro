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

package com.google.aliro

import com.google.aliro.core.b

interface Versions {
  val supportedVersions: ByteArray

  fun highestSupportedVersion(versions: ByteArray): Int?

  fun isVersionSupported(version: Int): Boolean
}

internal object VersionsImpl : Versions {
  internal const val PROTOCOL_VERSION_0100 = 0x0100
  internal const val PROTOCOL_VERSION_0007 = 0x0007

  private val SUPPORTED_VERSIONS_INT = listOf(PROTOCOL_VERSION_0100, PROTOCOL_VERSION_0007)

  @JvmField
  internal val SUPPORTED_VERSIONS: ByteArray = kotlin.run {
    SUPPORTED_VERSIONS_INT.map { toByteArray(it) }
      .reduce { versionList, versionBytes -> versionList + versionBytes }
  }

  override val supportedVersions: ByteArray = SUPPORTED_VERSIONS

  override fun isVersionSupported(version: Int): Boolean = SUPPORTED_VERSIONS_INT.contains(version)

  override fun highestSupportedVersion(versions: ByteArray): Int? {
    for (i in versions.indices step 2) {
      val version = toInt(versions[i], versions[i + 1])
      if (isVersionSupported(version)) {
        return version
      }
    }
    return null
  }

  @JvmStatic
  internal fun toByteArray(version: Int) =
    byteArrayOf(b(version.shr(8) and 0xff), b(version and 0xff))

  private fun toInt(b1: Byte, b2: Byte) = b1.toInt().shl(8) + b2.toInt()
}
