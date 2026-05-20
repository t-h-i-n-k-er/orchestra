package com.orchestra;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BroadcastReceiver that starts AgentService on device boot.
 *
 * <p>Registered in AndroidManifest.xml with BOOT_COMPLETED intent filter.
 * On Android 8.0+, foreground services must be started within 5 seconds of
 * the broadcast being received, or the system will throw an IllegalStateException.
 * We call startForegroundService() directly from the broadcast context.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "OrchestraBoot";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (action == null) {
            return;
        }

        Log.i(TAG, "Received broadcast: " + action);

        if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)
                || Intent.ACTION_USER_PRESENT.equals(action)) {

            Intent serviceIntent = new Intent(context, AgentService.class);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
}