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

import com.google.aliro.assertECPointEquals
import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroErrorCode
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Auth0FastDone
import com.google.aliro.core.Auth1Done
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.crypto.Cryptogram
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.endpoint.AliroContextImpl
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.google.aliro.endpoint.UserDeviceDatabase
import com.google.aliro.endpoint.UserDeviceProcessorImpl
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.Auth0Command
import com.google.aliro.messages.Auth0Response
import com.google.aliro.messages.Auth1Response
import com.google.aliro.messages.Auth1ResponsePlaintext
import com.google.aliro.messages.CommonVectors
import com.google.aliro.messages.ControlFlowCommand
import com.google.aliro.messages.ControlFlowResponse
import com.google.aliro.messages.ErrorResponse
import com.google.aliro.messages.ExpeditedFast
import com.google.aliro.messages.ExpeditedStandard
import com.google.aliro.messages.SelectCommand
import com.google.aliro.messages.SelectResponse
import com.google.aliro.messages.TransactionCode
import com.google.aliro.publicKeyFromHex
import com.google.aliro.toAliroIdentifier
import com.google.nfc.apdu.ApduCommand
import com.payneteasy.tlv.HexUtil.parseHex
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import io.mockk.spyk
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.interfaces.ECPublicKey

@OptIn(ExperimentalCoroutinesApi::class)
class AliroReaderTest {
  private val crypto = JvmCryptoImpl()
  private val readerConfiguration = ReaderConfiguration(
    identifier = ReaderIdentifier(parseHex(CommonVectors.READER_IDENTIFIER)),
    keypair = keypairFromHex(CommonVectors.READER_PUBLIC_KEY, CommonVectors.READER_PRIVATE_KEY),
    shouldSendFastTransaction = true,
  )
  private val knownUserDevices = mutableListOf<KnownUserDevice>()
  private val context = AliroReaderContextImpl(
    crypto = crypto,
    readerConfiguration = readerConfiguration,
    knownUserDevices = knownUserDevices,
    logger = mockk<AliroLogger>(relaxed = true),
  )
  private val transceiver = mockk<(ByteArray) -> ByteArray>()
  private val reader = AliroReader(context, transceiver)

  @Test
  fun `sendSelect sends a select command`() = runTest {
    val sendSlot = slot<(ByteArray)>()

    val response = SelectResponse(
      selectedAid = SelectCommand.AID,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      type = parseHex("0000")
    )

    every { transceiver(capture(sendSlot)) } returns response.toBytes()

    val result = reader.sendSelect()

    assertArrayEquals(parseHex(CommonVectors.SUPPORTED_VERSIONS), result)

    val expectedSend = SelectCommand(SelectCommand.AID)
    assertArrayEquals(expectedSend.toBytes(), sendSlot.captured)
  }

  @Test
  fun `sendSelect receives an error and returns null`() = runTest {
    val response = ErrorResponse(AliroErrorCode.GENERIC_ERROR)

    every { transceiver(any()) } returns response.toBytes()

    val result = reader.sendSelect()

    assertNull(result)
  }

  @Test
  fun `sendControlFlow sends an appropriate message`() = runTest {
    val sendSlot = slot<(ByteArray)>()

    val response = ControlFlowResponse()

    every { transceiver(capture(sendSlot)) } returns response.toBytes()

    reader.sendControlFlow(true)

    assertArrayEquals(ControlFlowCommand(true).toBytes(), sendSlot.captured)
  }

  @Test
  fun `checkCryptograms will return false when there are no stored readers`() {
    assertNull(
      reader.checkCryptograms(
        transactionId = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
        readerEPk = publicKeyFromHex(ExpeditedFast.READER_E_PUBLIC_KEY),
        endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
        parameter1 = 0x01.toByte(),
        transactionCode = TransactionCode.Unlock,
        deviceCryptogram = Cryptogram(
          parseHex(ExpeditedFast.CRYPTOGRAM),
        )
      )
    )
  }

  @Test
  fun `checkCryptograms will check stored readers against matching cryptograms`() {
    knownUserDevices.add(
      KnownUserDevice(
        publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY),
        FixedByteArray(parseHex("000000000000")),
      )
    )

    val devicePublicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY)

    knownUserDevices.add(
      KnownUserDevice(
        devicePublicKey,
        FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
      )
    )

    val result = reader.checkCryptograms(
      transactionId = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      protocolVersion = CommonVectors.PROTOCOL_VERSION,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      readerEPk = publicKeyFromHex(ExpeditedFast.READER_E_PUBLIC_KEY),
      endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
      parameter1 = 0x01.toByte(),
      transactionCode = TransactionCode.Unlock,
      deviceCryptogram = Cryptogram(parseHex(ExpeditedFast.CRYPTOGRAM))
    )

    assertECPointEquals((devicePublicKey as ECPublicKey).w, (result as ECPublicKey).w)
  }

  @Test
  fun `sendAuth0 handles a fast transaction with a known device`() = runTest {
    val sendSlot = slot<(ByteArray)>()
    val response = Auth0Response(
      endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
      cryptogram = Cryptogram(parseHex(ExpeditedFast.CRYPTOGRAM)),
    ).toBytes()

    knownUserDevices.add(
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT)),
      )
    )

    every { transceiver(capture(sendSlot)) } returns response
    val transactionId = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier()

    val result = reader.sendAuth0(
      readerEKeypair = keypairFromHex(
        ExpeditedFast.READER_E_PUBLIC_KEY,
        ExpeditedFast.READER_E_PRIVATE_KEY
      ),
      transactionId = transactionId,
      protocolVersion = CommonVectors.PROTOCOL_VERSION,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      action = TransactionCode.Unlock
    )

    assertEquals(Authorized::class, result::class)
    assertEquals(
      Auth0Command(
        isFastTransaction = true,
        transactionCode = TransactionCode.Unlock,
        protocolVersion = CommonVectors.PROTOCOL_VERSION,
        readerEPk = publicKeyFromHex(ExpeditedFast.READER_E_PUBLIC_KEY),
        readerIdentifier = readerConfiguration.identifier,
        transactionIdentifier = transactionId,
      ), Auth0Command.parse(crypto, ApduCommand.parse(sendSlot.captured))
    )
  }

  @Test
  fun `sendAuth0 handles a standard transaction`() = runTest {
    val sendSlot = slot<(ByteArray)>()
    val response = Auth0Response(
      endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
      cryptogram = Cryptogram(parseHex(ExpeditedFast.CRYPTOGRAM)),
    ).toBytes()

    every { transceiver(capture(sendSlot)) } returns response

    val result = reader.sendAuth0(
      readerEKeypair = keypairFromHex(
        ExpeditedFast.READER_E_PUBLIC_KEY,
        ExpeditedFast.READER_E_PRIVATE_KEY
      ),
      transactionId = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      protocolVersion = CommonVectors.PROTOCOL_VERSION,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      action = TransactionCode.Unlock
    )

    val expectedAuth1 = NeedAuth1(
      protocolVersion = CommonVectors.PROTOCOL_VERSION,
      supportedVersions = parseHex(CommonVectors.SUPPORTED_VERSIONS),
      readerEKeypair = keypairFromHex(
        ExpeditedFast.READER_E_PUBLIC_KEY,
        ExpeditedFast.READER_E_PRIVATE_KEY
      ),
      endpointEPk = publicKeyFromHex(ExpeditedFast.DEVICE_E_PUBLIC_KEY),
      transactionIdentifier = ExpeditedFast.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      flag = FixedByteArray(parseHex("0101")),
    )
    assertEquals(expectedAuth1, result)
  }

  @Test
  fun `transact performs a standard transaction`() = runTest {
    val db = mockk<UserDeviceDatabase>()
    val crypto = spyk(JvmCryptoImpl())
    val logger = mockk<AliroLogger>(relaxed = true)
    val userDeviceContext = AliroContextImpl(crypto, db, logger)

    val endpoint = Endpoint(
      keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY)
    )

    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    every { db.findPersistentKey(any()) } returns null
    every { db.dummyPersistentKey() } returns FixedByteArray(ByteArray(32))
    every { db.storePersistentKey(any(), any()) } just runs
    every { db.findEndpoints(readerGroup.readerGroupIdentifier) } returns setOf(endpoint)
    every { db.findReaderGroup(readerGroup.readerGroupIdentifier) } returns readerGroup
    every { db.debug() } returns "debug"

    val userDeviceProcessor = UserDeviceProcessorImpl(userDeviceContext)

    val reader = AliroReader(context) {
      val command = userDeviceProcessor.parseApduCommand(it)
      userDeviceProcessor.processCommand(command).toBytes()
    }

    val result = reader.transact(TransactionCode.Unlock)

    assertEquals(AliroReader.TransactionResult.Authorized::class, result::class)
  }

  @Test
  fun `transact performs a fast transaction`() = runTest {
    val db = mockk<UserDeviceDatabase>()
    val crypto = JvmCryptoImpl()
    val logger = mockk<AliroLogger>(relaxed = true)
    val userDeviceContext = AliroContextImpl(crypto, db, logger)

    val endpoint = Endpoint(
      keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY)
    )

    knownUserDevices.add(
      KnownUserDevice(
        publicKey = publicKeyFromHex(CommonVectors.DEVICE_PUBLIC_KEY),
        kPersistent = FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT))
      )
    )

    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    every { db.findPersistentKey(readerConfiguration.identifier) } returns FixedByteArray(
      parseHex(ExpeditedStandard.K_PERSISTENT)
    )

    every { db.storePersistentKey(any(), any()) } just runs
    every { db.findEndpoints(readerGroup.readerGroupIdentifier) } returns setOf(endpoint)
    every { db.findReaderGroup(readerGroup.readerGroupIdentifier) } returns readerGroup
    every { db.debug() } returns "debug"

    val userDeviceProcessor = UserDeviceProcessorImpl(userDeviceContext)

    val reader = AliroReader(context) {
      val command = userDeviceProcessor.parseApduCommand(it)
      val response = userDeviceProcessor.processCommand(command)

      if (response is Auth0Response) {
        assertTrue(userDeviceContext.transaction.state is Auth0FastDone)
      }

      response.toBytes()
    }

    val result = reader.transact(TransactionCode.Unlock)

    assertEquals(AliroReader.TransactionResult.Authorized::class, result::class)
  }

  @Test
  fun `transact throws an error when versions are incompatible`() = runTest {
    val db = mockk<UserDeviceDatabase>()
    val crypto = spyk(JvmCryptoImpl())
    val logger = mockk<AliroLogger>(relaxed = true)
    val userDeviceContext = AliroContextImpl(crypto, db, logger)

    val endpoint = Endpoint(
      keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY)
    )

    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    every { db.findPersistentKey(any()) } returns null
    every { db.dummyPersistentKey() } returns FixedByteArray(ByteArray(32))
    every { db.storePersistentKey(any(), any()) } just runs
    every { db.findEndpoints(readerGroup.readerGroupIdentifier) } returns setOf(endpoint)
    every { db.findReaderGroup(readerGroup.readerGroupIdentifier) } returns readerGroup
    every { db.debug() } returns "debug"

    val userDeviceProcessor = UserDeviceProcessorImpl(userDeviceContext)

    val reader = AliroReader(context) {
      val command = userDeviceProcessor.parseApduCommand(it)

      if (command is SelectCommand) {
        // fake a bad version response
        SelectResponse(
          selectedAid = SelectCommand.AID,
          supportedVersions = byteArrayOf(0x00, 0x00),
          type = byteArrayOf(0x00, 0x00)
        ).toBytes()
      } else {
        userDeviceProcessor.processCommand(command).toBytes()
      }
    }

    assertThrows(AliroError::class.java) {
      runBlocking {
        reader.transact(TransactionCode.Unlock)
      }
    }
  }

  @Test
  fun `transact returns unauthorized when a reader is unknown to the endpoint`() = runTest {
    val db = mockk<UserDeviceDatabase>()
    val crypto = spyk(JvmCryptoImpl())
    val logger = mockk<AliroLogger>(relaxed = true)
    val userDeviceContext = AliroContextImpl(crypto, db, logger)

    val endpoint = Endpoint(
      keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY)
    )

    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    every { db.findPersistentKey(any()) } returns null
    every { db.dummyPersistentKey() } returns FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT))
    every { db.storePersistentKey(any(), any()) } just runs
    every { db.findEndpoints(readerGroup.readerGroupIdentifier) } returns setOf(endpoint)
    every { db.findReaderGroup(readerGroup.readerGroupIdentifier) } returns null
    every { db.dummyReaderGroup() } returns KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.DUMMY_ENDPOINT_READER_PUBLIC_KEY)
    )
    every { db.debug() } returns "debug"

    val userDeviceProcessor = UserDeviceProcessorImpl(userDeviceContext)

    val reader = AliroReader(context) {
      val command = userDeviceProcessor.parseApduCommand(it)
      userDeviceProcessor.processCommand(command).toBytes()
    }

    val result = reader.transact(TransactionCode.Unlock)

    assertEquals(AliroReader.TransactionResult.Unauthorized, result)
  }

  @Test
  fun `transact returns unauthorized when an endpoint signature cannot be verified`() = runTest {
    val db = mockk<UserDeviceDatabase>()
    val crypto = spyk(JvmCryptoImpl())
    val logger = mockk<AliroLogger>(relaxed = true)
    val userDeviceContext = AliroContextImpl(crypto, db, logger)

    val endpoint = Endpoint(
      keypairFromHex(CommonVectors.DEVICE_PUBLIC_KEY, CommonVectors.DEVICE_PRIVATE_KEY)
    )

    val readerGroup = KnownReaderGroup(
      CommonVectors.READER_GROUP_ID.toAliroIdentifier(),
      publicKeyFromHex(CommonVectors.READER_PUBLIC_KEY)
    )

    every { db.findPersistentKey(any()) } returns null
    every { db.dummyPersistentKey() } returns FixedByteArray(parseHex(ExpeditedStandard.K_PERSISTENT))
    every { db.storePersistentKey(any(), any()) } just runs
    every { db.findEndpoints(readerGroup.readerGroupIdentifier) } returns setOf(endpoint)
    every { db.findReaderGroup(readerGroup.readerGroupIdentifier) } returns readerGroup
    every { db.debug() } returns "debug"

    val userDeviceProcessor = UserDeviceProcessorImpl(userDeviceContext)

    val reader = AliroReader(context) {
      val command = userDeviceProcessor.parseApduCommand(it)
      val result = userDeviceProcessor.processCommand(command)
      val deviceState = userDeviceContext.transaction.state

      if (result is Auth1Response && deviceState is Auth1Done) {
        val fakeChannelState = deviceState.secureChannelState.copy(counter = 1)
        val decrypted = result.decrypt(context, fakeChannelState)

        val badSignature = Auth1ResponsePlaintext(
          endpointPk = decrypted.endpointPk,
          endpointSignature = FixedByteArray(ByteArray(32)),
          keySlot = null
        )
        val (_, response) = Auth1Response.encrypt(
          crypto = crypto,
          secureChannelState = fakeChannelState,
          plaintext = badSignature
        )
        response.toBytes()
      } else {
        result.toBytes()
      }
    }

    val result = reader.transact(TransactionCode.Unlock)

    assertEquals(AliroReader.TransactionResult.Unauthorized, result)
  }
}
