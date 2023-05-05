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

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.crypto.JvmCommonCrypto
import com.google.aliro.crypto.JvmCommonCrypto.Companion.KEYPAIR_PARAMETER_SPEC
import com.google.crypto.tink.subtle.EllipticCurves
import com.google.nfc.apdu.ApduCommand
import com.google.nfc.apdu.ApduResponse
import com.payneteasy.tlv.HexUtil
import org.junit.Assert
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec


fun String.hexToBigInteger() = BigInteger(1, HexUtil.parseHex(this))
fun String.toAliroIdentifier() = AliroIdentifier(HexUtil.parseHex(this))

fun ecPointFromHex(x: String, y: String): ECPoint =
  ECPoint(x.hexToBigInteger(), y.hexToBigInteger())

fun publicKeyFromHex(x: String, y: String): PublicKey {
  val factory = KeyFactory.getInstance(JvmCommonCrypto.KEYPAIR_ALGORITHM)

  return factory.generatePublic(
    ECPublicKeySpec(ecPointFromHex(x, y), KEYPAIR_PARAMETER_SPEC)
  )
}

fun publicKeyFromHex(publicHex: String): PublicKey {
  val factory = KeyFactory.getInstance(JvmCommonCrypto.KEYPAIR_ALGORITHM)

  val point = EllipticCurves.pointDecode(
    EllipticCurves.CurveType.NIST_P256,
    EllipticCurves.PointFormatType.UNCOMPRESSED,
    HexUtil.parseHex(publicHex)
  )
  return factory.generatePublic(ECPublicKeySpec(point, KEYPAIR_PARAMETER_SPEC))
}

fun responseFromHex(responseHex: String): ApduResponse =
  ApduResponse.parse(HexUtil.parseHex(responseHex))

fun commandFromHex(commandHex: String): ApduCommand =
  ApduCommand.parse(HexUtil.parseHex(commandHex))

fun secretAesKeyFromHex(s: String): SecretKey =
  SecretKeySpec(HexUtil.parseHex(s), "AES")

fun keypairFromHex(x: String, y: String, private: String): KeyPair {
  val point = ecPointFromHex(x, y)

  val factory = KeyFactory.getInstance(JvmCommonCrypto.KEYPAIR_ALGORITHM)

  val public = factory.generatePublic(ECPublicKeySpec(point, KEYPAIR_PARAMETER_SPEC))
  val pk = factory.generatePrivate(
    ECPrivateKeySpec(private.hexToBigInteger(), KEYPAIR_PARAMETER_SPEC)
  )

  return KeyPair(public, pk)
}

fun keypairFromHex(publicHex: String, privateHex: String): KeyPair {
  val factory = KeyFactory.getInstance(JvmCommonCrypto.KEYPAIR_ALGORITHM)

  val point = EllipticCurves.pointDecode(
    EllipticCurves.CurveType.NIST_P256,
    EllipticCurves.PointFormatType.UNCOMPRESSED,
    HexUtil.parseHex(publicHex)
  )
  val public = factory.generatePublic(ECPublicKeySpec(point, KEYPAIR_PARAMETER_SPEC))
  val pk = factory.generatePrivate(
    ECPrivateKeySpec(privateHex.hexToBigInteger(), KEYPAIR_PARAMETER_SPEC)
  )

  return KeyPair(public, pk)
}

fun assertEqualsHex(expected: String, actual: ByteArray) =
  Assert.assertArrayEquals(HexUtil.parseHex(expected), actual)

fun assertECPointEquals(expected: ECPoint, actual: ECPoint) {
  Assert.assertEquals(expected.affineX, actual.affineX)
  Assert.assertEquals(expected.affineY, actual.affineY)
}

fun assertECPKEquals(expected: PublicKey, actual: PublicKey) {
  assertECPointEquals(
    (expected as ECPublicKey).w,
    (actual as ECPublicKey).w,
  )
}

