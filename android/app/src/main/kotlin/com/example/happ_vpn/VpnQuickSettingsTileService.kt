package com.example.happ_vpn

import android.content.Intent
import android.net.VpnService
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class VpnQuickSettingsTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refreshTileState()
    }

    override fun onClick() {
        super.onClick()

        // فقط اگر برای اولین بار هنوز مجوز VPN اندروید داده نشده، صفحه مجوز باز شود
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            val openIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivityAndCollapse(openIntent)
            return
        }

        // وضعیت را قبل از اجرای واقعی تغییر نده؛ در غیر این صورت entrypoint پس‌زمینه
        // وضعیتِ جدید را می‌خواند و ممکن است دقیقاً عمل معکوس را اجرا کند.
        qsTile?.apply {
            label = "SHIN"
        }

        // قطع و وصل کاملاً در پس‌زمینه بدون باز کردن برنامه
        MainActivity.triggerBackgroundToggle(applicationContext)
    }

    private fun refreshTileState() {
        val prefs = getSharedPreferences(MainActivity.PREFS_NAME, Context.MODE_PRIVATE)
        val isConnected = prefs.getBoolean(MainActivity.KEY_CONNECTED, false)
        qsTile?.apply {
            state = if (isConnected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            label = "SHIN"
            updateTile()
        }
    }
}