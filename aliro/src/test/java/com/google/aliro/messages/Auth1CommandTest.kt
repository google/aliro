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
import com.google.aliro.assertECPointEquals
import com.google.aliro.core.AliroError
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.Auth0StandardDone
import com.google.aliro.core.Auth1Done
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.Initial
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.core.SecureChannelKeys
import com.google.aliro.core.SecureChannelState
import com.google.aliro.core.Transaction
import com.google.aliro.core.TransactionState
import com.google.aliro.crypto.JvmCryptoImpl
import com.google.aliro.endpoint.AliroUserDeviceContext
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.google.aliro.endpoint.UserDeviceDatabase
import com.google.aliro.keypairFromHex
import com.google.aliro.messages.CommonVectors.DEVICE_PRIVATE_KEY
import com.google.aliro.messages.CommonVectors.DEVICE_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.DUMMY_ENDPOINT_READER_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.READER_GROUP_ID
import com.google.aliro.messages.CommonVectors.READER_PUBLIC_KEY
import com.google.aliro.messages.CommonVectors.READER_SUB_GROUP_ID
import com.google.aliro.publicKeyFromHex
import com.google.aliro.secretAesKeyFromHex
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
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.security.interfaces.ECPublicKey

@RunWith(JUnit4::class)
class Auth1CommandTest {
  private val context = mockk<AliroUserDeviceContext>()
  private val userDeviceDb = mockk<UserDeviceDatabase>()
  private val transaction = mockk<Transaction>()
  private val versions = mockk<Versions>()
  private val logger = mockk<AliroLogger>(relaxed = true)

  // The context is made-up, but the crypto is real.
  private val crypto = spyk(JvmCryptoImpl())
  private val stateCapture = slot<TransactionState>()

  @Before
  fun init() {
    every { context.crypto } returns crypto
    every { context.database } returns userDeviceDb
    every { context.transaction } returns transaction
    every { context.logger } returns logger
    every { context.versions } returns versions
    every { transaction.moveToState(capture(stateCapture)) } just runs
    every { userDeviceDb.debug() } returns ""
    every { userDeviceDb.storePersistentKey(any(), any()) } just runs
    every { versions.supportedVersions } returns byteArrayOf(0x01, 0x00)
  }

  @Test
  fun `Auth1Command can be parsed`() {
    val actual =
      Auth1Command.parse(ApduCommand.parse(HexUtil.parseHex(ExpeditedStandard.AUTH1_COMMAND)))

    val expected = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
    )

    assertEquals(expected, actual)
  }

  @Test
  fun `Auth1Command can be round-tripped`() {
    val expected = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
      certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
    )
    val actual = Auth1Command.parse(ApduCommand.parse(expected.toBytes()))

    assertEquals(expected, actual)
    assertEquals(expected.hashCode(), actual.hashCode())
    assertEquals(expected.toString(), actual.toString())
  }

  @Test
  fun `Auth1Command process standard`() {
    every {
      userDeviceDb.findReaderGroup(READER_ID.groupIdentifier)
    } returns READER

    every { transaction.state } returns AUTH0_STANDARD_DONE

    // Method under test
    val command = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE))
    )
    val result = command.process(context)

    assertEquals(Auth1Done::class.java, stateCapture.captured::class.java)
    assertEquals(AliroResponse.SW1_NO_FURTHER_QUALIFICATION, result.sw1)
    assertEquals(0x00.toByte(), result.sw2)

    val decrypted = result.decrypt(context, CHANNEL_STATE)

    val expectedDeviceKey = publicKeyFromHex(DEVICE_PUBLIC_KEY) as ECPublicKey
    assertECPointEquals(expectedDeviceKey.w, (decrypted.endpointPk as ECPublicKey).w)
  }

  @Test
  fun `process ensures that the state is correct`() {
    val command = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
    )

    every { transaction.state } returns Initial

    assertThrows(AliroError::class.java) {
      command.process(context)
    }
  }

  @Test
  fun `process uses a dummy reader group if none are found`() {
    val command = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
    )

    every {
      userDeviceDb.findReaderGroup(any())
    } returns null

    val dummyReaderGroup = KnownReaderGroup(
      readerGroupIdentifier = "00000000000000000000000000000000".toAliroIdentifier(),
      readerPublicKey = publicKeyFromHex(publicHex = DUMMY_ENDPOINT_READER_PUBLIC_KEY),
    )

    every { transaction.state } returns AUTH0_STANDARD_DONE
    every { userDeviceDb.dummyReaderGroup() } returns dummyReaderGroup

    // the signature can't be valid if a dummy reader group is used
    assertThrows(AliroError::class.java) {
      command.process(context)
    }

    verify {
      userDeviceDb.dummyReaderGroup()
    }
  }

  @Test
  fun `process throws an error if the signature is invalid`() {
    every {
      userDeviceDb.findReaderGroup(READER_ID.groupIdentifier)
    } returns READER

    every { transaction.state } returns AUTH0_STANDARD_DONE

    val command = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(ByteArray(64)),
    )

    assertThrows(AliroError::class.java) {
      command.process(context)
    }
  }

  @Test
  fun `equals and hashCode function as expected`() {
    val command = Auth1Command(
      isEndpointPublicKey = true,
      readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
      certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
    )

    assertEquals(
      command,
      Auth1Command(
        isEndpointPublicKey = true,
        readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
        certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
      )
    )

    assertEquals(
      command.hashCode(),
      Auth1Command(
        isEndpointPublicKey = true,
        readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
        certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
      ).hashCode()
    )

    // isEndpointPublicKey
    assertNotEquals(
      command,
      Auth1Command(
        isEndpointPublicKey = false,
        readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
        certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
      )
    )

    // readerSignature
    assertNotEquals(
      command,
      Auth1Command(
        isEndpointPublicKey = true,
        readerSignature = ReaderSignature(ByteArray(64)),
        certificateData = HexUtil.parseHex(FAKE_CERT_DATA),
      )
    )

    // certificateData
    assertNotEquals(
      command,
      Auth1Command(
        isEndpointPublicKey = true,
        readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
        certificateData = HexUtil.parseHex("CAFE"),
      )
    )

    assertNotEquals(
      command,
      Auth1Command(
        isEndpointPublicKey = true,
        readerSignature = ReaderSignature(HexUtil.parseHex(ExpeditedStandard.READER_SIGNATURE)),
        certificateData = null,
      )
    )
  }

  companion object {
    const val FAKE_CERT_DATA = "DECAF BAD"

    private val READER_ID = ReaderIdentifier(
      HexUtil.parseHex(READER_GROUP_ID) + HexUtil.parseHex(READER_SUB_GROUP_ID),
    )
    private val READER_PK = publicKeyFromHex(READER_PUBLIC_KEY)

    private val READER = KnownReaderGroup(
      readerGroupIdentifier = READER_ID.groupIdentifier,
      readerPublicKey = READER_PK,
    )

    private val KEYS = SecureChannelKeys(
      exchangeSkReader = secretAesKeyFromHex(ExpeditedStandard.EXCHANGE_SK_READER),
      exchangeSkDevice = secretAesKeyFromHex(ExpeditedStandard.EXCHANGE_SK_DEVICE),
      urSk = secretAesKeyFromHex(ExpeditedStandard.UR_SK),
      bleSk = secretAesKeyFromHex(ExpeditedStandard.BLE_SK),
      stepUpSk = secretAesKeyFromHex(ExpeditedStandard.STEP_UP_SK),
    )

    private val CHANNEL_STATE = SecureChannelState(keys = KEYS)

    private val AUTH0_STANDARD_DONE = Auth0StandardDone(
      secureChannelState = CHANNEL_STATE,
      transactionIdentifier = ExpeditedStandard.TRANSACTION_IDENTIFIER.toAliroIdentifier(),
      endpoint = Endpoint(keypairFromHex(DEVICE_PUBLIC_KEY, DEVICE_PRIVATE_KEY)),
      endpointEKeypair = keypairFromHex(
        ExpeditedStandard.DEVICE_E_PUBLIC_KEY,
        ExpeditedStandard.DEVICE_E_PRIVATE_KEY
      ),
      protocolVersion = 0x100,
      readerIdentifier = ReaderIdentifier(
        HexUtil.parseHex(READER_GROUP_ID) + HexUtil.parseHex(READER_SUB_GROUP_ID),
      ),
      flag = FixedByteArray(byteArrayOf(0x00, 0x01)),
      readerEpk = publicKeyFromHex(ExpeditedStandard.READER_E_PUBLIC_KEY),
    )
  }
}
