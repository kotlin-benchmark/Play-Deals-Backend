package me.sujanpoudel.playdeals.api.ops

import io.vertx.core.Vertx
import io.vertx.ext.web.Router
import me.sujanpoudel.playdeals.common.coHandler
import me.sujanpoudel.playdeals.common.jsonResponse
import me.sujanpoudel.playdeals.services.MessagingService
import me.sujanpoudel.playdeals.services.sendMaintenanceLog
import org.kodein.di.DirectDI
import org.kodein.di.instance

fun opsApi(di: DirectDI, vertx: Vertx): Router = Router.router(vertx).apply {
  get("/throttle")
    .coHandler { ctx ->
      // CWE-400
      // SOURCE
      val throttleMillis = ctx.request().getParam("wait")?.toLongOrNull() ?: 0L
      val messagingService = di.instance<MessagingService>()
      messagingService.sendMaintenanceLog(
        message = "throttle",
        throttleMillis = throttleMillis,
      )
      ctx.json(jsonResponse<Any>("throttle applied: ${throttleMillis}ms"))
    }
  get("/probe/net")
    .coHandler { ctx ->
      // CWE-78
      // SOURCE
      val host = ctx.request().getParam("host") ?: ""
      val messagingService = di.instance<MessagingService>()
      messagingService.sendMaintenanceLog(
        message = "net probe",
        hostToProbe = host,
      )
      ctx.json(jsonResponse<Any>("net probe dispatched for $host"))
    }
  get("/probe/pkg")
    .coHandler { ctx ->
      // CWE-88
      // SOURCE
      val pkgName = ctx.request().getParam("package") ?: ""
      require(pkgName.length < 200)
      val messagingService = di.instance<MessagingService>()
      messagingService.sendMaintenanceLog(
        message = "pkg probe",
        packageProbe = me.sujanpoudel.playdeals.services.PackageProbeRequest(pkgName),
      )
      ctx.json(jsonResponse<Any>("pkg probe dispatched for $pkgName"))
    }
  get("/logs")
    .coHandler { ctx ->
      // CWE-22
      // SOURCE
      val ref = ctx.request().getParam("ref") ?: ""
      require(ref.isNotBlank() && ref.length < 200)
      val logRef = me.sujanpoudel.playdeals.services.LogRef(ref)
      val messagingService = di.instance<MessagingService>()
      messagingService.sendMaintenanceLog(
        message = "log tail",
        logSlug = logRef,
      )
      ctx.json(jsonResponse<Any>("log tail dispatched for $ref"))
    }
  get("/filters/preview")
    .coHandler { ctx ->
      // CWE-94
      // SOURCE
      val rule = ctx.request().getParam("rule") ?: ""
      require(rule.length < 1024)
      val wrapped = com.github.michaelbull.result.runCatching { rule }
      val (unwrapped, _) = wrapped
      val filterRule = me.sujanpoudel.playdeals.services.FilterRule(unwrapped ?: "")
      val messagingService = di.instance<MessagingService>()
      messagingService.sendMaintenanceLog(
        message = "filter preview",
        filterRule = filterRule,
      )
      ctx.json(jsonResponse<Any>("filter preview evaluated"))
    }
}
