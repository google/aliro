package com.google.aliro.android.sampleapp

import android.content.ComponentName
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.google.aliro.messages.SelectCommand
import com.payneteasy.tlv.HexUtil

class ReaderActivity : AppCompatActivity() {
  private val readerViewModel: ReaderViewModel by viewModels()

  private lateinit var adapter: NfcAdapter

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_reader)

    adapter = NfcAdapter.getDefaultAdapter(this)

    val statusView = findViewById<TextView>(R.id.status)
    readerViewModel.statusLiveData.observe(this) { status ->
      statusView.text = status
    }

    val lockStatus = findViewById<TextView>(R.id.lock_status)
    readerViewModel.isLocked.observe(this) { isLocked ->
      lockStatus.setText(if (isLocked) R.string.lock_locked else R.string.lock_unlocked)
    }

    val endpointPublicKeyStatus = findViewById<TextView>(R.id.endpoint_public_key)
    readerViewModel.endpointPublicKeyHex.observe(this) { endpointPublicKeyHex ->
      endpointPublicKeyStatus.text = getString(R.string.endpoint_pk_status, endpointPublicKeyHex)
    }

    logDebugInfo()
    readerViewModel.logReaderInfo()
  }

  override fun onPause() {
    adapter.disableReaderMode(this)

    super.onPause()
  }

  override fun onResume() {
    super.onResume()

    enableReader()
  }

  private fun enableReader() {
    adapter.enableReaderMode(
      this,
      readerViewModel::onTagDiscovered,
      NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
      null
    )
  }

  private fun logDebugInfo() {
    val hasHce =
      applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION)
    Log.d(TAG, "This device supports HCE: $hasHce")

    val emulation = CardEmulation.getInstance(adapter)
    val aid = HexUtil.toHexString(SelectCommand.AID)
    val isDefault =
      emulation.isDefaultServiceForAid(ComponentName(this, AliroHCEService::class.java), aid)
    Log.d(TAG, "This is the default for AID $aid: $isDefault")
  }

  companion object {
    private val TAG = ReaderActivity::class.simpleName
  }
}