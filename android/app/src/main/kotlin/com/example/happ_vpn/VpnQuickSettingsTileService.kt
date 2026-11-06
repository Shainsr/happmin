package com.example.happ_vpn

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class VpnQuickSettingsTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    @Suppress("DEPRECATION")
    override fun onClick() {
        super.onClick()
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            action = "${packageName}.QUICK_TILE_TOGGLE"
            putExtra(MainActivity.EXTRA_ACTION, MainActivity.ACTION_TOGGLE_VPN)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                741,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            startActivityAndCollapse(launchIntent)
        }
    }

    private fun refreshTile() {
        val connected = getSharedPreferences(MainActivity.NATIVE_PREFS, MODE_PRIVATE)
            .getBoolean(MainActivity.KEY_CONNECTED, false)
        qsTile?.let { tile ->
            tile.label = "Happ VPN"
            tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_vpn)
            tile.state = if (connected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            tile.updateTile()
        }
    }
}
