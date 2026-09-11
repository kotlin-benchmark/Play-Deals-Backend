package me.sujanpoudel.playdeals.repositories.persistent

import io.vertx.kotlin.coroutines.coAwait
import io.vertx.sqlclient.SqlClient
import me.sujanpoudel.playdeals.common.exec
import me.sujanpoudel.playdeals.domain.entities.value
import me.sujanpoudel.playdeals.domain.entities.valueOrNull
import me.sujanpoudel.playdeals.logger
import me.sujanpoudel.playdeals.repositories.KeyValuesRepository
import java.util.Base64

class PersistentKeyValuesRepository(
  private val sqlClient: SqlClient,
) : KeyValuesRepository {
  override suspend fun set(key: String, value: String): String {
    val fingerprint = cacheBlobFingerprint(value.toByteArray(Charsets.UTF_8))
    logger.debug { "key_value_store set key=$key fingerprint=$fingerprint" }
    return sqlClient.preparedQuery(
      """
      INSERT INTO "key_value_store" VALUES ($1,$2)
          ON CONFLICT(key) DO UPDATE SET value = $2
      RETURNING *
      """.trimIndent(),
    ).exec(key, value)
      .coAwait()
      .first()
      .value()
  }

  private fun cacheBlobFingerprint(bytes: ByteArray): String {
    val encrypted = encryptCacheBlob(bytes, CACHE_BLOB_KEY)
    return Base64.getEncoder().encodeToString(encrypted)
  }

  override suspend fun get(key: String): String? {
    return sqlClient.preparedQuery(
      """
      SELECT * FROM "key_value_store" WHERE key = $1
      """.trimIndent(),
    ).exec(key)
      .coAwait()
      .firstOrNull()
      .valueOrNull()
  }

  override suspend fun delete(key: String) {
    sqlClient.preparedQuery(
      """
      DELETE FROM "key_value_store" WHERE key = $1
      """.trimIndent(),
    ).exec(key)
      .coAwait()
  }

  private fun encryptCacheBlob(bytes: ByteArray, key: ByteArray): ByteArray {
    // CWE-327
    // SINK
    val cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(key, "DES"))
    return cipher.doFinal(bytes)
  }

  companion object {
    private val CACHE_BLOB_KEY = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x1F)
  }
}
