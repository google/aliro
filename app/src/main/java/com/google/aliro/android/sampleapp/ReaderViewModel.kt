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

package com.google.aliro.android.sampleapp

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.aliro.android.AndroidCrypto
import com.google.aliro.core.AliroLogger
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.crypto.encodeBasic
import com.google.aliro.crypto.xByteArray
import com.google.aliro.messages.TransactionCode
import com.google.aliro.reader.AliroReader
import com.google.aliro.reader.AliroReaderContextImpl
import com.google.aliro.reader.KnownUserDevice
import com.google.aliro.reader.ReaderConfiguration
import com.payneteasy.tlv.HexUtil
import com.payneteasy.tlv.HexUtil.toFormattedHexString
import com.payneteasy.tlv.HexUtil.toHexString
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.launch

class ReaderViewModel : ViewModel() {
  val statusLiveData = MutableLiveData<String>()
  val isLocked = MutableLiveData(true)
  val endpointPublicKeyHex = MutableLiveData<String>()

  private val logger = object : AliroLogger {
    override fun logDebug(message: String) {
      statusLog.log("D: $message")
      Log.d(ReaderViewModel::class.simpleName, message)
    }

    override fun logError(message: String, exception: Throwable?) {
      statusLog.log("E: $message")
      Log.e(ReaderViewModel::class.simpleName, message, exception)
    }
  }

  private val statusLog = StatusLogger(statusLiveData)

  private val crypto = AndroidCrypto()

  private val readerIdentifier =
    ReaderIdentifier(HexUtil.parseHex(READER_GROUP_IDENTIFIER + READER_SUB_GROUP_IDENTIFIER))
  private val knownUserDevices = mutableListOf<KnownUserDevice>()
  private val readerKeypair = crypto.generateOrRetrieveKeypair(KEY_ALIAS_READER)

  private val readerConfig = ReaderConfiguration(
    identifier = readerIdentifier,
    keypair = readerKeypair,
  )

  private val context = AliroReaderContextImpl(
    crypto = crypto,
    readerConfiguration = readerConfig,
    knownUserDevices = knownUserDevices,
    logger = logger,
  )

  private val errorHandler = CoroutineExceptionHandler { _, throwable ->
    logger.logError("Error communicating with other device", throwable)
  }

  fun logReaderInfo() {
    logger.logDebug("Reader identifier: $readerIdentifier")
    logger.logDebug("Reader public key: ${toHexString(readerKeypair.public.encodeBasic())}")
  }

  fun onTagDiscovered(anyTechTag: Tag) {
    IsoDep.get(anyTechTag)?.let { isoDepTag ->
      logger.logDebug(
        "On tag discovered: (ID: ${toHexString(anyTechTag.id)}, tech: ${
          anyTechTag.techList.joinToString(",")
        })"
      )

      viewModelScope.launch(errorHandler) {
        transactTag(isoDepTag)
      }
    }
  }

  private suspend fun transactTag(isoDepTag: IsoDep) {
    isoDepTag.use { tag ->
      tag.connect()
      val aliroReader = AliroReader(context, tag::transceive)

      val action = if (isLocked.value == true) {
        TransactionCode.Unlock
      } else {
        TransactionCode.Lock
      }

      when (val result = aliroReader.transact(action)) {
        is AliroReader.TransactionResult.Authorized -> {
          logger.logDebug("Transaction authorized! $result")
          val lastEight = result.endpointPublicKey.xByteArray.takeLast(8).toByteArray()
          logger.logDebug("Success. Last 8 bytes of public key X is: ${toHexString(lastEight)}")

          when (action) {
            TransactionCode.Lock -> isLocked.postValue(true)
            TransactionCode.Unlock -> isLocked.postValue(false)
            else -> {}
          }
          endpointPublicKeyHex.postValue(toFormattedHexString(result.endpointPublicKey.encodeBasic()))
        }

        is AliroReader.TransactionResult.Unauthorized -> {
          endpointPublicKeyHex.postValue("UNAUTHORIZED")
          logger.logDebug("Unauthorized")
        }
      }
    }
  }

  companion object {
    const val KEY_ALIAS_READER = "reader-keypair"

    const val READER_GROUP_IDENTIFIER = "ca922d974bf1e4ddb106fc0d7793db6b"
    const val READER_SUB_GROUP_IDENTIFIER = "efe89cd4c2483d5beecc1c394b9e8163"
  }
}

private class StatusLogger(private val statusOutput: MutableLiveData<String>) {
  private val statusLines = StringBuffer()

  fun log(message: String) {
    statusLines.append('\n')
    statusLines.append(message)
    statusOutput.postValue(statusLines.toString())
  }
}
