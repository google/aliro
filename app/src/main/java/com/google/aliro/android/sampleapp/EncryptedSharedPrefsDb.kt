package com.google.aliro.android.sampleapp

import android.content.Context
import android.content.SharedPreferences
import androidx.annotation.WorkerThread
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.crypto.AliroCrypto
import com.payneteasy.tlv.HexUtil

class EncryptedSharedPrefsDb private constructor(crypto: AliroCrypto, private val filename: String) :
  InMemoryDb(crypto) {
  private lateinit var db: SharedPreferences

  /**
   * Load the encrypted shared preferences. This must be called before any other methods get called.
   */
  @WorkerThread
  fun load(applicationContext: Context) {
    val mainKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    db = EncryptedSharedPreferences.create(
      filename,
      mainKeyAlias,
      applicationContext,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
  }

  override fun findPersistentKey(readerIdentifier: ReaderIdentifier): FixedByteArray? {
    return db.getString(persistentKeyKey(readerIdentifier), null)?.let {
      FixedByteArray(HexUtil.parseHex(it))
    }
  }

  override fun storePersistentKey(readerIdentifier: ReaderIdentifier, kPersistent: FixedByteArray) {
    db.edit().apply {
      putString(persistentKeyKey(readerIdentifier), kPersistent.toHexString())
    }.apply()
  }

  private fun persistentKeyKey(readerIdentifier: ReaderIdentifier) =
    "pk-${readerIdentifier.groupIdentifier.identifier.toHexString()}"

  override fun debug() = "DB contents: ${db.all}"

  companion object {
    fun getOrCreate(crypto: AliroCrypto, filename: String): EncryptedSharedPrefsDb =
      EncryptedSharedPrefsDb(crypto, filename)
  }
}