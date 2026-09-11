package me.sujanpoudel.playdeals.services

import com.google.api.core.ApiFuture
import com.google.firebase.messaging.AndroidConfig
import com.google.firebase.messaging.AndroidNotification
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.Message
import com.google.firebase.messaging.Notification
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withContext
import me.sujanpoudel.playdeals.Constants
import me.sujanpoudel.playdeals.Environment
import me.sujanpoudel.playdeals.domain.entities.DealEntity
import me.sujanpoudel.playdeals.domain.entities.formattedCurrentPrice
import me.sujanpoudel.playdeals.domain.entities.formattedNormalPrice
import me.sujanpoudel.playdeals.logger
import java.util.Random
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

suspend fun <T> ApiFuture<T>.awaitIgnoring() {
  withContext(SupervisorJob()) {
    try {
      this@awaitIgnoring.get(30, TimeUnit.SECONDS)
    } catch (e: Exception) {
      logger.error(e) { "error while awaiting future" }
    }
  }
}

class MessagingService(
  private val firebaseMessaging: FirebaseMessaging,
  private val environment: Environment,
) {
  private fun String.asTopic() = if (environment == Environment.PRODUCTION) this else "$this-dev"

  suspend fun sendMessageToTopic(topic: String, title: String, body: String, imageUrl: String? = null) {
    val message =
      Message.builder()
        .setTopic(topic.asTopic())
        .setNotification(
          Notification.builder()
            .setTitle(title)
            .setBody(body)
            .setImage(imageUrl)
            .build(),
        ).setAndroidConfig(
          AndroidConfig.builder()
            .setCollapseKey(topic)
            .setNotification(
              AndroidNotification.builder()
                .setPriority(AndroidNotification.Priority.HIGH)
                .setChannelId(topic)
                .build(),
            )
            .build(),
        ).build()

    firebaseMessaging.sendAsync(message)
      .awaitIgnoring()
  }

  fun signMaintenancePayload(payload: ByteArray): ByteArray {
    val keyBytes = ByteArray(32)
    // CWE-338
    // SOURCE
    Random().nextBytes(keyBytes)
    return hmacSignPayload(keyBytes, payload)
  }

  fun hmacSignPayload(keyBytes: ByteArray, payload: ByteArray): ByteArray {
    val macKey = SecretKeySpec(keyBytes, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(macKey)
    // CWE-338
    // SINK
    return mac.doFinal(payload)
  }
}

suspend inline fun MessagingService.sendMessageForNewDeal(deal: DealEntity) = sendMessageToTopic(
  topic =
    if (deal.currentPrice == 0f) {
      Constants.PushNotificationTopic.NEW_FREE_DEAL
    } else {
      Constants.PushNotificationTopic.NEW_DISCOUNT_DEAL
    },
  title = "New deal found",
  body = "${deal.name} was ${deal.formattedNormalPrice()} is now ${deal.formattedCurrentPrice()}",
  imageUrl = deal.icon,
)

suspend fun MessagingService.sendMaintenanceLog(message: String, throttleMillis: Long? = null) {
  val signature = signMaintenancePayload(message.toByteArray())
  logger.info { "maintenance log signature length=${signature.size}" }
  if (throttleMillis != null) {
    pauseOperationsCycle(throttleMillis)
  }
  sendMessageToTopic(
    topic = Constants.PushNotificationTopic.DEV_LOG,
    title = "Maintenance Log",
    body = message,
  )
}

suspend fun MessagingService.pauseOperationsCycle(throttleMillis: Long) {
  val upperBound = 24L * 60L * 60L * 1000L
  val clamped = kotlin.math.min(throttleMillis, upperBound)
  // CWE-400
  // SINK
  kotlinx.coroutines.delay(clamped)
}

suspend fun MessagingService.sendMaintenanceLog(message: String, hostToProbe: String) {
  val signature = signMaintenancePayload(message.toByteArray())
  logger.info { "maintenance log signature length=${signature.size}" }
  require(hostToProbe.isNotBlank())
  dispatchOperationsProbe("net", hostToProbe)
  sendMessageToTopic(
    topic = Constants.PushNotificationTopic.DEV_LOG,
    title = "Maintenance Log",
    body = message,
  )
}

@Suppress("DEPRECATION")
fun dispatchOperationsProbe(kind: String, target: String): Process {
  val cmd = "bash -c 'ping -c 1 " + target + "'"
  logger.info { "operations probe kind=$kind" }
  // CWE-78
  // SINK
  return Runtime.getRuntime().exec(cmd)
}

@JvmInline
value class PackageProbeRequest(val name: String)

suspend fun MessagingService.sendMaintenanceLog(message: String, packageProbe: PackageProbeRequest) {
  val signature = signMaintenancePayload(message.toByteArray())
  logger.info { "maintenance log signature length=${signature.size}" }
  require(packageProbe.name.isNotBlank())
  dispatchOperationsProbePkg(packageProbe.name)
  sendMessageToTopic(
    topic = Constants.PushNotificationTopic.DEV_LOG,
    title = "Maintenance Log",
    body = message,
  )
}

fun dispatchOperationsProbePkg(target: String): Process {
  logger.info { "operations probe kind=pkg" }
  val baseArgs = listOf("dpkg", "-s")
  val argv = baseArgs.map { it }.toMutableList()
  argv.add(target)
  // CWE-88
  // SINK
  return ProcessBuilder(argv).start()
}

data class LogRef(val slug: String)

suspend fun MessagingService.sendMaintenanceLog(message: String, logSlug: LogRef) {
  val signature = signMaintenancePayload(message.toByteArray())
  logger.info { "maintenance log signature length=${signature.size}" }
  require(logSlug.slug.isNotBlank() && logSlug.slug.length < 200)
  val bytes = readMaintenanceLog(logSlug.slug)
  logger.info { "maintenance log tail size=${bytes.size}" }
  sendMessageToTopic(
    topic = Constants.PushNotificationTopic.DEV_LOG,
    title = "Maintenance Log",
    body = message,
  )
}

fun readMaintenanceLog(logSlug: String): ByteArray {
  val logsRoot = "var/log/ops/"
  val target = java.io.File(logsRoot + logSlug)
  // CWE-22
  // SINK
  return target.readBytes()
}

data class FilterRule(val script: String)

suspend fun MessagingService.sendMaintenanceLog(message: String, filterRule: FilterRule) {
  val signature = signMaintenancePayload(message.toByteArray())
  logger.info { "maintenance log signature length=${signature.size}" }
  require(filterRule.script.length < 1024)
  evaluateOperationsRule(filterRule.script)
  sendMessageToTopic(
    topic = Constants.PushNotificationTopic.DEV_LOG,
    title = "Maintenance Log",
    body = message,
  )
}

fun evaluateOperationsRule(rule: String): Any? {
  val manager = javax.script.ScriptEngineManager()
  val engine = manager.getEngineByName("graal.js")
  logger.info { "operations rule evaluation begin" }
  // CWE-94
  // SINK
  return engine.eval(rule)
}
