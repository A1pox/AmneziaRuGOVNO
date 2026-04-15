package org.amnezia.vpn

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

private const val TG_PROXY_NOTIFICATION_ID = 1438
private const val TG_PROXY_NOTIFICATION_CHANNEL_ID = "org.amnezia.vpn.notifications"
private const val EXTRA_PORT = "port"

class TelegramProxyForegroundService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val port = intent?.getIntExtra(EXTRA_PORT, 1443) ?: 1443
        startForeground(TG_PROXY_NOTIFICATION_ID, buildNotification(port))
        return START_STICKY
    }

    override fun onDestroy() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun buildNotification(port: Int): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, AmneziaActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, TG_PROXY_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_amnezia_round)
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentTitle(getString(R.string.telegramProxyNotificationTitle))
            .setContentText(getString(R.string.telegramProxyNotificationMessage, port))
            .setContentIntent(openIntent)
            .build()
    }
}
