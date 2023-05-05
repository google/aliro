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

import com.google.aliro.Versions
import com.google.aliro.VersionsImpl
import com.google.aliro.assertECPKEquals
import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Auth0Done
import com.google.aliro.core.Auth0FastDone
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.Initial
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.core.SelectDone
import com.google.aliro.core.Transaction
import com.google.aliro.core.TransactionState
import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.google.aliro.endpoint.UserDeviceDatabase
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors.DEVICE_PRIVATE_KEY
import com.google.aliro.messages.CommonVectors.DEVICE_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.DUMMY_ENDPOINT_PRIVATE_KEY
import com.google.aliro.messages.CommonVectors.DUMMY_ENDPOINT_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.DUMMY_ENDPOINT_READER_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.DUMMY_K_PERSISTENT
import com.google.aliro.messages.CommonVectors.READER_GROUP_ID
import com.google.aliro.messages.CommonVectors.READER_IDENTIFIER
import com.google.aliro.messages.CommonVectors.READER_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.READER_SUB_GROUP_ID
import com.google.aliro.publicKeyFromHex
import com.google.aliro.toAliroIdentifier
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.HexUtil
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import io.mockk.spyk
import io.mockk.verify
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class Auth0CommandTest {
  private val context = mockk<AliroUserDeviceContext>()
  private val userDeviceDb = mockk<UserDeviceDatabase>()
  private val crypto = spyk(JvmCryptoImpl())
  private val transaction = mockk<Transaction>()
  private val logger = mockk<AliroLogger>(relaxed = true)
  private val versions = mockk<Versions>()
  private val stateCapture = slot<TransactionState>()

  @Before
  fun init() {
    every { context.crypto } returns crypto
    every { context.database } returns userDeviceDb
    every { context.transaction } returns transaction
    every { context.logger } returns logger
    every { context.versions } returns versions

    every { versions.supportedVersions } returns byteArrayOf(0x01, 0x00)
    every { versions.highestSupportedVersion(any()) } returns 0x100
    every { versions.isVersionSupported(any()) } returns true

    every { transaction.moveToState(capture(stateCapture)) } just runs
    every { transaction.state } returns SelectDone

    every { userDeviceDb.debug() } returns ""
  }

  @Test
  fun `test AUTH0 command round trip`() {
    val expected = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER))
    )
    val actual = Auth0Command.parse(context.crypto, ApduCommand.parse(expected.toBytes()))

    assertEquals(expected, actual)
  }

  @Test
  fun `test AUTH0 command parse`() {
    val actual =
      Auth0Command.parse(
        context.crypto,
        ApduCommand.parse(HexUtil.parseHex(ExpeditedStandard.AUTH0_COMMAND))
      )

    val readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY)

    val expected = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = 0x0100,
      readerEPk = readerEPk,
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    assertEquals(expected, actual)
  }

  @Test
  fun `test AUTH0 command process with a fast transaction`() {
    val readerGroup = AliroIdentifier(HexUtil.parseHex(READER_GROUP_ID))
    val readerIdentifier =
      ReaderIdentifier(readerGroup, AliroIdentifier(HexUtil.parseHex(READER_SUB_GROUP_ID)))

    val command =
      Auth0Command.parse(
        context.crypto,
        ApduCommand.parse(HexUtil.parseHex(ExpeditedFast.AUTH0_COMMAND))
      )

    val endpointKeypair = keypairFromHex(DEVICE_PUBLIC_KEY, DEVICE_PRIVATE_KEY)
    val knownReaderGroup = KnownReaderGroup(
      readerGroup,
      publicKeyFromHex(READER_PUBLIC_KEY),
    )
    val endpoint = Endpoint(endpointKeypair)

    every { userDeviceDb.findEndpoints(readerGroup) } returns setOf(endpoint)
    every { userDeviceDb.findReaderGroup(readerGroup) } returns knownReaderGroup
    every { userDeviceDb.findPersistentKey(readerIdentifier) } returns FixedByteArray(
      HexUtil.parseHex(ExpeditedStandard.K_PERSISTENT)
    )

    val endpointEKeyPair = keypairFromHex(
      ExpeditedFast.DEVICE_E_PUBLIC_KEY,
      ExpeditedFast.DEVICE_E_PRIVATE_KEY,
    )

    every { crypto.generateEphemeralKeypair() } returns endpointEKeyPair

    // Method under test
    val response = command.process(context)

    assertECPKEquals(endpointEKeyPair.public, response.endpointEPk)
    assertEquals(Cryptogram(HexUtil.parseHex(ExpeditedFast.CRYPTOGRAM)), response.cryptogram)
  }

  @Test
  fun `test AUTH0 command process with a standard transaction`() {
    val readerGroup = AliroIdentifier(HexUtil.parseHex(READER_GROUP_ID))
    val readerIdentifier =
      ReaderIdentifier(readerGroup, AliroIdentifier(HexUtil.parseHex(READER_SUB_GROUP_ID)))

    val command = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    val endpointKeypair = keypairFromHex(
      DEVICE_PUBLIC_KEY,
      DEVICE_PRIVATE_KEY,
    )

    val knownReaderGroup = KnownReaderGroup(
      readerGroup,
      publicKeyFromHex(READER_PUBLIC_KEY),
    )
    val endpoint = Endpoint(endpointKeypair)

    every { userDeviceDb.findEndpoints(readerGroup) } returns setOf(endpoint)
    every { userDeviceDb.findReaderGroup(readerGroup) } returns knownReaderGroup
    every { userDeviceDb.findPersistentKey(readerIdentifier) } returns FixedByteArray(
      HexUtil.parseHex(DUMMY_K_PERSISTENT)
    )

    val endpointEKeyPair = keypairFromHex(
      ExpeditedStandard.DEVICE_E_PUBLIC_KEY,
      ExpeditedStandard.DEVICE_E_PRIVATE_KEY,
    )

    every { crypto.generateEphemeralKeypair() } returns endpointEKeyPair

    // Method under test
    val response = command.process(context)

    assertECPKEquals(endpointEKeyPair.public, response.endpointEPk)

    assertNull(response.cryptogram)
  }

  @Test
  fun `process ensures that the transaction is in the right state`() {
    val command = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    every { transaction.state } returns Initial

    assertThrows(AliroError::class.java) {
      command.process(context)
    }
  }

  @Test
  fun `process ensures that the protocolVersion is supported`() {
    val badVersion = 0x23
    val command = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = badVersion,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    every { versions.isVersionSupported(badVersion) } returns false

    assertThrows(AliroError::class.java) {
      command.process(context)
    }
  }

  @Test
  fun `process will use a dummy endpoint when no endpoints are found`() {
    val command = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )
    val dummyEndpoint = mockk<Endpoint>()
    every { dummyEndpoint.endpointKeypair } returns keypairFromHex(
      publicHex = DUMMY_ENDPOINT_PUBLIC_KEY,
      privateHex = DUMMY_ENDPOINT_PRIVATE_KEY
    )

    every { userDeviceDb.findEndpoints(any()) } returns emptySet()
    every { userDeviceDb.dummyEndpoint() } returns dummyEndpoint

    command.process(context)
  }

  @Test
  fun `process will pick a random endpoint when no endpoints are found`() {
    val command = Auth0Command(
      isFastTransaction = false,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )
    val endpoint1 = mockk<Endpoint>()
    every { endpoint1.endpointKeypair } returns keypairFromHex(
      publicHex = DUMMY_ENDPOINT_PUBLIC_KEY,
      privateHex = DUMMY_ENDPOINT_PRIVATE_KEY
    )

    val endpoint2 = mockk<Endpoint>()
    every { endpoint2.endpointKeypair } returns keypairFromHex(
      publicHex = DEVICE_PUBLIC_KEY,
      privateHex = DEVICE_PRIVATE_KEY,
    )

    val endpointSet = setOf(endpoint1, endpoint2)

    every { userDeviceDb.findEndpoints(any()) } returns endpointSet

    command.process(context)

    val state = stateCapture.captured as Auth0Done
    assertTrue(state.endpoint == endpoint1 || state.endpoint == endpoint2)
  }

  @Test
  fun `process will use a dummy reader when no reader groups are found`() {
    val command = Auth0Command(
      isFastTransaction = true,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    val readerGroup = AliroIdentifier(HexUtil.parseHex(READER_GROUP_ID))
    val endpoint = Endpoint(keypairFromHex(DEVICE_PUBLIC_KEY, DEVICE_PRIVATE_KEY))

    every { userDeviceDb.findEndpoints(readerGroup) } returns setOf(endpoint)

    val dummyReaderGroup = KnownReaderGroup(
      readerGroupIdentifier = "00000000000000000000000000000000".toAliroIdentifier(),
      readerPublicKey = publicKeyFromHex(publicHex = DUMMY_ENDPOINT_READER_PUBLIC_KEY),
    )

    val dummyPersistentKey = FixedByteArray(HexUtil.parseHex(DUMMY_K_PERSISTENT))

    every { userDeviceDb.findReaderGroup(any()) } returns null
    every { userDeviceDb.findPersistentKey(any()) } returns null

    every { userDeviceDb.dummyReaderGroup() } returns dummyReaderGroup
    every { userDeviceDb.dummyPersistentKey() } returns dummyPersistentKey

    command.process(context)

    assertTrue(stateCapture.captured is Auth0FastDone)

    verify {
      userDeviceDb.dummyReaderGroup()
      userDeviceDb.dummyPersistentKey()
    }
  }

  @Test
  fun `toString yields a useful string`() {
    val readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER))
    val command = Auth0Command(
      isFastTransaction = true,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = readerIdentifier,
      transactionIdentifier = AliroIdentifier(HexUtil.parseHex(ExpeditedStandard.TRANSACTION_IDENTIFIER)),
    )

    command.toString().let {
      assertTrue(it.contains("Auth0Command"))
      assertTrue(it.contains("isFastTransaction=true"))
      assertTrue(it.contains("Unlock"))
      assertTrue(it.contains(readerIdentifier.toString()))
      assertTrue(it.contains(ExpeditedStandard.TRANSACTION_IDENTIFIER))
    }
  }

  @Test
  fun `equals and hashCode function properly`() {
    val command1 = Auth0Command(
      isFastTransaction = true,
      transactionCode = TransactionCode.Unlock,
      protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
      readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
      readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
      transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
    )

    assertEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    assertEquals(
      command1.hashCode(), Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      ).hashCode()
    )

    // isFastTransaction
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = false,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    // transactionCode
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Lock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    // protocolVersion
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0007,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    // readerEPk
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.DEVICE_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    // readerIdentifier
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(ByteArray(32)),
        transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      )
    )

    // transactionIdentifier
    assertNotEquals(
      command1, Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = VersionsImpl.PROTOCOL_VERSION_0100,
        readerEPk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
        readerIdentifier = ReaderIdentifier(HexUtil.parseHex(READER_IDENTIFIER)),
        transactionIdentifier = AliroIdentifier(ByteArray(16))
      )
    )
  }
}
