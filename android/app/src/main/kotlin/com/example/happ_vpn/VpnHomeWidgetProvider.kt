package com.example.happ_vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

class VpnHomeWidgetProvider : AppWidgetProvider() {

    companion object {
        const val ACTION_WIDGET_TOGGLE = "com.example.happ_vpn.ACTION_WIDGET_TOGGLE"
    }

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (appWidgetId in appWidgetIds) {
            updateWidgetView(context, appWidgetManager, appWidgetId)
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action == ACTION_WIDGET_TOGGLE) {
            // وضعیت را اینجا toggle نکن؛ تابع پس‌زمینه باید وضعیت واقعی قبلی را بخواند.
            // نتیجهٔ واقعی از callback هسته به ویجت منعکس می‌شود.

            // اجرای قطع/وصل در پس‌زمینه بدون باز شدن MainActivity
            MainActivity.triggerBackgroundToggle(context.applicationContext)
        }
    }

    private fun updateWidgetView(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int
    ) {
        val prefs = context.getSharedPreferences(MainActivity.PREFS_NAME, Context.MODE_PRIVATE)
        val isConnected = prefs.getBoolean(MainActivity.KEY_CONNECTED, false)

        val views = RemoteViews(context.packageName, R.layout.widget_vpn)
        views.setInt(
            R.id.widget_root,
            "setBackgroundResource",
            if (isConnected) R.drawable.widget_vpn_background_on else R.drawable.widget_vpn_background
        )

        // استفاده از getBroadcast به جای getActivity روی R.id.widget_root تا برنامه باز نشود
        val toggleIntent = Intent(context, VpnHomeWidgetProvider::class.java).apply {
            action = ACTION_WIDGET_TOGGLE
        }
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            0,
            toggleIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        views.setOnClickPendingIntent(R.id.widget_root, pendingIntent)

        appWidgetManager.updateAppWidget(appWidgetId, views)
    }
}