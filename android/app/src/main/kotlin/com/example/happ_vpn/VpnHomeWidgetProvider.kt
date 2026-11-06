package com.example.happ_vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

class VpnHomeWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray,
    ) {
        updateAll(context)
    }

    companion object {
        fun updateAll(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val provider = ComponentName(context, VpnHomeWidgetProvider::class.java)
            val widgetIds = manager.getAppWidgetIds(provider)
            val prefs = context.getSharedPreferences(MainActivity.NATIVE_PREFS, Context.MODE_PRIVATE)
            val connected = prefs.getBoolean(MainActivity.KEY_CONNECTED, false)
            val status = prefs.getString(MainActivity.KEY_STATUS, "DISCONNECTED") ?: "DISCONNECTED"

            widgetIds.forEach { widgetId ->
                val views = RemoteViews(context.packageName, R.layout.widget_vpn)
                views.setTextViewText(R.id.widget_status, if (connected) "متصل و فعال" else "اتصال برقرار نیست")
                views.setTextViewText(R.id.widget_action, if (connected) "قطع اتصال" else "اتصال")
                views.setTextViewText(
                    R.id.widget_detail,
                    when (status) {
                        "CONNECTING" -> "در حال اتصال…"
                        "CONNECTED" -> "VPN روشن است"
                        else -> "برای تغییر وضعیت لمس کنید"
                    },
                )

                val toggleIntent = Intent(context, MainActivity::class.java).apply {
                    action = "${context.packageName}.HOME_WIDGET_TOGGLE"
                    putExtra(MainActivity.EXTRA_ACTION, MainActivity.ACTION_TOGGLE_VPN)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                }
                val pendingIntent = PendingIntent.getActivity(
                    context,
                    widgetId,
                    toggleIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
                views.setOnClickPendingIntent(R.id.widget_root, pendingIntent)
                views.setOnClickPendingIntent(R.id.widget_action, pendingIntent)
                manager.updateAppWidget(widgetId, views)
            }
        }
    }
}
