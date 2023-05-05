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

import com.google.crypto.tink.subtle.EllipticCurves
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

fun PublicKey.encodeBasic(): ByteArray =
  EllipticCurves.pointEncode(
    EllipticCurves.CurveType.NIST_P256,
    EllipticCurves.PointFormatType.UNCOMPRESSED,
    (this as ECPublicKey).w
  )

val PublicKey.xByteArray: ByteArray
  get() = this.encodeBasic().sliceArray(1 until 33)
