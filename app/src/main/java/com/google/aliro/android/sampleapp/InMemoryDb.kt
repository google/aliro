package com.google.aliro.android.sampleapp

import com.google.aliro.core.AliroIdentifier
import com.google.aliro.core.FixedByteArray
import com.google.aliro.core.ReaderIdentifier
import com.google.aliro.crypto.AliroCrypto
import com.google.aliro.endpoint.Endpoint
import com.google.aliro.endpoint.KnownReaderGroup
import com.google.aliro.endpoint.UserDeviceDatabase

open class InMemoryDb(crypto: AliroCrypto) : UserDeviceDatabase {
  private val readerGroups = mutableMapOf<AliroIdentifier, KnownReaderGroup>()
  private val kPersistent = mutableMapOf<ReaderIdentifier, FixedByteArray>()
  private val endpointMap = mutableMapOf<AliroIdentifier, MutableSet<Endpoint>>()

  private val dummyEndpoint = Endpoint(crypto.generateEphemeralKeypair())
  private val dummyReader = KnownReaderGroup(
    AliroIdentifier.randomIdentifier(crypto),
    crypto.generateEphemeralKeypair().public,
  )
  private val dummyPersistentKey =
    FixedByteArray(crypto.randomBytes(KnownReaderGroup.K_PERSISTENT_SIZE))

  override fun findEndpoints(readerGroupIdentifier: AliroIdentifier) =
    endpointMap[readerGroupIdentifier] ?: emptySet()

  override fun dummyEndpoint(): Endpoint = dummyEndpoint

  override fun findReaderGroup(readerGroupIdentifier: AliroIdentifier): KnownReaderGroup? =
    readerGroups[readerGroupIdentifier]

  override fun storeReaderGroup(endpoint: Endpoint, knownReaderGroup: KnownReaderGroup) {
    val key = knownReaderGroup.readerGroupIdentifier
    readerGroups[key] = knownReaderGroup

    endpointMap[key] = endpointMap.getOrDefault(key, mutableSetOf()).apply {
      add(endpoint)
    }
  }

  override fun dummyReaderGroup() = dummyReader

  override fun findPersistentKey(readerIdentifier: ReaderIdentifier): FixedByteArray? =
    kPersistent[readerIdentifier]

  override fun storePersistentKey(readerIdentifier: ReaderIdentifier, kPersistent: FixedByteArray) {
    this.kPersistent[readerIdentifier] = kPersistent
  }

  override fun dummyPersistentKey() = dummyPersistentKey

  override fun debug() = "kPersistent: $kPersistent"
}