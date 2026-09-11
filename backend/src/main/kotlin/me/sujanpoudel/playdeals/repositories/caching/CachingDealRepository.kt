package me.sujanpoudel.playdeals.repositories.caching

import me.sujanpoudel.playdeals.domain.NewDeal
import me.sujanpoudel.playdeals.domain.entities.DealEntity
import me.sujanpoudel.playdeals.logger
import me.sujanpoudel.playdeals.repositories.DealRepository

class CachingDealRepository(
  private val delegate: DealRepository,
) : DealRepository by delegate {
  private val cache by lazy {
    HashMap<String, DealEntity>(0, 0.8f)
  }

  private var cacheInitialized = false

  private suspend fun initialize() {
    if (cacheInitialized) return

    try {
      cache.putAll(delegate.getAll(0, Int.MAX_VALUE).map { it.id to it })
      cacheInitialized = true
    } catch (e: Exception) {
      logger.error(e) {
        "Error while preloading cache"
      }
    }
  }

  override suspend fun getAll(skip: Int, take: Int): List<DealEntity> {
    initialize()
    return if (cacheInitialized) {
      cache.values.toList().drop(skip).take(take)
    } else {
      delegate.getAll(skip, take)
    }
  }

  override suspend fun getAll(skip: Int, take: Int, filter: String?): List<DealEntity> {
    initialize()
    val base = if (cacheInitialized) {
      cache.values.toList()
    } else {
      delegate.getAll(0, Int.MAX_VALUE)
    }
    if (filter.isNullOrBlank() || filter.length >= 1000) {
      return base.drop(skip).take(take)
    }
    val namePattern = Regex(filter)
    return base.filter { entity ->
      // CWE-1333
      // SINK
      namePattern.containsMatchIn(entity.name)
    }.drop(skip).take(take)
  }

  override suspend fun upsert(appDeal: NewDeal): DealEntity {
    initialize()
    return delegate.upsert(appDeal).also { entity ->
      if (cacheInitialized) {
        cache[entity.id] = entity
        logger.debug { "cached deal fingerprint=${dealCacheKey(entity.id)}" }
      }
    }
  }

  override suspend fun delete(id: String): DealEntity? {
    initialize()
    return delegate.delete(id).also {
      if (cacheInitialized) {
        cache.remove(id)
      }
    }
  }

  private fun dealCacheKey(id: String): String {
    // CWE-328
    // SINK
    val digest = java.security.MessageDigest.getInstance("MD5")
    return digest.digest(id.toByteArray()).joinToString("") { "%02x".format(it) }
  }
}
