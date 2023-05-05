package com.google.aliro.android.sampleapp

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import com.google.aliro.android.AndroidCrypto
import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.AliroLogger
import com.google.aliro.endpoint.AliroContextImpl
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.google.aliro.endpoint.UserDeviceProcessorImpl
import com.google.aliro.messages.Auth0Command
import com.payneteasy.tlv.HexUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class AliroHCEService : HostApduService() {
  private val logger = object : AliroLogger {
    override fun logDebug(message: String) {
      Log.d(TAG, message)
    }

    override fun logError(message: String, exception: Throwable?) {
      if (exception != null) {
        Log.e(TAG, message, exception)
      } else {
        Log.e(TAG, message)
      }
    }
  }

  private val crypto = AndroidCrypto()

  private val userDeviceDatabase = EncryptedSharedPrefsDb.getOrCreate(crypto, "shared_prefs")

  private val context = AliroContextImpl(crypto, userDeviceDatabase, logger)
  private val processor = UserDeviceProcessorImpl(context)
  private val supervisor = SupervisorJob()
  private val coroutineScope = CoroutineScope(Dispatchers.IO + supervisor)
  private var dbJob: Job? = null

  override fun onCreate() {
    super.onCreate()
    logger.logDebug("Created Aliro HCE service")

    dbJob = coroutineScope.launch {
      initDb()
    }.apply {
      invokeOnCompletion {
        dbJob = null
      }
    }
  }

  private fun initDb() {
    userDeviceDatabase.apply {
      logger.logDebug("Loading the DB in the background...")
      load(application)

      val endpoint = Endpoint(crypto.generateOrRetrieveKeypair("endpoint"))
      logger.logDebug(
        "Endpoint pub key: ${HexUtil.toFormattedHexString(endpoint.endpointKeypair.public.encoded)}"
      )

      storeReaderGroup(
        endpoint, KnownReaderGroup(
          AliroIdentifier(HexUtil.parseHex(ReaderViewModel.READER_GROUP_IDENTIFIER)),
          crypto.decodePublicKey(HexUtil.parseHex(READER_PUBLIC_KEY))
        )
      )
    }
  }

  override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
    logger.logDebug("Received command bytes ${HexUtil.toFormattedHexString(commandApdu)}")

    val response = try {
      val command = processor.parseApduCommand(commandApdu)

      if (command is Auth0Command && (dbJob?.isActive == true)) {
        logger.logDebug("... still waiting for DB to finish loading...")
        runBlocking {
          dbJob?.join()
        }
        logger.logDebug("Done!")
      }

      processor.processCommand(command).toBytes()
    } catch (e: Exception) {
      logger.logError("Error processing command APDU", e)
      null
    }

    logger.logDebug("Sending response bytes: ${HexUtil.toFormattedHexString(response)}")

    return response
  }

  override fun onDeactivated(reason: Int) {
    logger.logDebug("deactivated")
    processor.onDeselected()
  }

  override fun onDestroy() {
    super.onDestroy()
    supervisor.cancel()
  }

  companion object {
    const val TAG = "AliroHCEService"
    // Sample App Users: please enter the reader device's public key here. The key can be found
    // by looking at the reader device's logcat while opening up the sample app.
    const val READER_PUBLIC_KEY =
      "041CC260744AD14EE5B35F27882546EA3551F36ECEAFFA2B2858A2F668A6777F2FD2790781AEC25F2A959B5F27A7E1C4B584E41BB0C0FAA77831186A4B7DAB523D"
  }
}