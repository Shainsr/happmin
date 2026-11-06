package com.example.happ_vpn

import android.content.ComponentName
import android.content.Intent
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.service.quicksettings.TileService

class MainActivity : FlutterActivity() {
    companion object {
        const val CHANNEL = "com.example.happ_vpn/quick_controls"
        const val EXTRA_ACTION = "quick_action"
        const val ACTION_TOGGLE_VPN = "toggleVpn"
        const val NATIVE_PREFS = "happ_vpn_native_state"
        const val KEY_CONNECTED = "connected"
        const val KEY_STATUS = "status"
        const val KEY_PENDING_ACTION = "pending_action"
    }

    private var quickControlsChannel: MethodChannel? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        quickControlsChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        quickControlsChannel?.setMethodCallHandler { call, result ->
            when (call.method) {
                "setConnectionState" -> {
                    val connected = call.argument<Boolean>("connected") ?: false
                    val status = call.argument<String>("status") ?: "DISCONNECTED"
                    getSharedPreferences(NATIVE_PREFS, MODE_PRIVATE).edit()
                        .putBoolean(KEY_CONNECTED, connected)
                        .putString(KEY_STATUS, status)
                        .apply()
                    VpnHomeWidgetProvider.updateAll(this)
                    requestTileRefresh()
                    result.success(null)
                }

                "consumePendingAction" -> result.success(consumePendingAction())
                else -> result.notImplemented()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val action = intent.getStringExtra(EXTRA_ACTION) ?: return
        intent.removeExtra(EXTRA_ACTION)
        setIntent(intent)

        getSharedPreferences(NATIVE_PREFS, MODE_PRIVATE).edit()
            .putString(KEY_PENDING_ACTION, action)
            .apply()
        quickControlsChannel?.invokeMethod("quickToggleVpn", null)
    }

    private fun consumePendingAction(): String? {
        val intentAction = intent?.getStringExtra(EXTRA_ACTION)
        if (!intentAction.isNullOrBlank()) {
            intent?.removeExtra(EXTRA_ACTION)
            return intentAction
        }

        val prefs = getSharedPreferences(NATIVE_PREFS, MODE_PRIVATE)
        val pending = prefs.getString(KEY_PENDING_ACTION, null)
        prefs.edit().remove(KEY_PENDING_ACTION).apply()
        return pending
    }

    private fun requestTileRefresh() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            TileService.requestListeningState(
                this,
                ComponentName(this, VpnQuickSettingsTileService::class.java),
            )
        }
    }
}
