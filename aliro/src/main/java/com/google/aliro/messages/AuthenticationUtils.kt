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

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.crypto.xByteArray
import com.payneteasy.tlv.BerTag
import com.payneteasy.tlv.BerTlvBuilder
import java.security.PrivateKey
import java.security.PublicKey

internal fun auth1Info(
  readerEPk: PublicKey,
  endpointEPk: PublicKey,
  transactionIdentifier: AliroIdentifier,
  flag: FixedByteArray,
  versionBytes: ByteArray,
  supportedVersions: ByteArray,
  type: String,
) = readerEPk.xByteArray +
  endpointEPk.xByteArray +
  transactionIdentifier.toBytes() +
  0x5E + // contactless interface
  flag.bytes +
  type.encodeToByteArray() +
  0x5C.toByte() +
  versionBytes.size.toByte() +
  versionBytes +
  0x5C.toByte() +
  supportedVersions.size.toByte() +
  supportedVersions

internal fun generateAuthenticationData(
  readerIdentifier: ReaderIdentifier,
  readerEPublicKey: PublicKey,
  endpointEPublicKey: PublicKey,
  transactionIdentifier: AliroIdentifier,
  usage: ByteArray,
): ByteArray = BerTlvBuilder().apply {
  addBytes(BerTag(TAG_READER_IDENTIFIER), readerIdentifier.toBytes())
  addBytes(BerTag(TAG_ENDPOINT_EPK_X), endpointEPublicKey.xByteArray)
  addBytes(BerTag(TAG_READER_EPK_X), readerEPublicKey.xByteArray)
  addBytes(BerTag(TAG_TRANSACTION_IDENTIFIER), transactionIdentifier.toBytes())
  addBytes(BerTag(TAG_USAGE), usage)
}.buildArray()

internal fun generateAuthenticationSignature(
  crypto: AliroCrypto,
  signingPrivateKey: PrivateKey,
  readerIdentifier: ReaderIdentifier,
  readerEPublicKey: PublicKey,
  endpointEPublicKey: PublicKey,
  transactionIdentifier: AliroIdentifier,
  usage: ByteArray,
): ByteArray {
  val data = generateAuthenticationData(
    readerIdentifier = readerIdentifier,
    readerEPublicKey = readerEPublicKey,
    endpointEPublicKey = endpointEPublicKey,
    transactionIdentifier = transactionIdentifier,
    usage = usage,
  )

  return crypto.generateSignature(data, signingPrivateKey)
}

internal val READER_USAGE =
  byteArrayOf(0x41.toByte(), 0x5D.toByte(), 0x95.toByte(), 0x69.toByte())

internal val ENDPOINT_USAGE =
  byteArrayOf(0x4E.toByte(), 0x88.toByte(), 0x7B.toByte(), 0x4c.toByte())

private const val TAG_READER_IDENTIFIER = 0x4D
private const val TAG_ENDPOINT_EPK_X = 0x86
private const val TAG_READER_EPK_X = 0x87
private const val TAG_TRANSACTION_IDENTIFIER = 0x4C
private const val TAG_USAGE = 0x93

