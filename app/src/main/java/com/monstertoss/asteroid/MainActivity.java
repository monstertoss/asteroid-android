package com.monstertoss.asteroid;

import android.app.ActivityManager;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private static String TAG = "MainActivity";
    static String PACKAGE_NAME = "com.monstertoss.asteroid";
    static String NOTIFICATION_CHANNEL = PACKAGE_NAME;

    private Button startStopButton;

    // Helper method to check if the server is running
    private boolean isServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (serviceClass.getName().equals(service.service.getClassName())) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Create notification channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager mNotificationManager = (NotificationManager) getApplicationContext().getSystemService(Context.NOTIFICATION_SERVICE);
            CharSequence name = getString(R.string.notificationChannel);
            int importance = NotificationManager.IMPORTANCE_LOW;
            NotificationChannel mChannel = new NotificationChannel(MainActivity.NOTIFICATION_CHANNEL, name, importance);
            mNotificationManager.createNotificationChannel(mChannel);
        }

        startStopButton = findViewById(R.id.startStopButton);

        // Execute start stop based on whether the server is running
        startStopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if(isServiceRunning(ServerService.class)) {
                    stopServer();
                } else {
                    startServer();
                }
            }
        });
        startStopButton.setText(getString(isServiceRunning(ServerService.class) ? R.string.stopServer : R.string.startServer));

        // Broadcast receiver for when the server has stopped. This is used to set the UI in the correct state
        LocalBroadcastManager.getInstance(this).registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(final Context context, Intent intent) {
                Log.d(TAG, "Received server stop");
                startStopButton.setText(getString(R.string.startServer));
            }
        }, new IntentFilter("MainActivity.stopped"));

        // Broadcast receiver that is called when an unknown key is sent to the server.
        // It is used to show a popup to confirm the public key.
        LocalBroadcastManager.getInstance(this).registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(final Context context, Intent intent) {
                final String fingerprint = intent.getStringExtra("fingerprint");

                Log.d(TAG, "Popup to confirm key: " + fingerprint);

                // Build an alert, set the layout from confirm_key_layout.xml and set the fingerprint that was sent with the Intent
                final AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                builder.setTitle(R.string.confirmKeyTitle);

                View layout = getLayoutInflater().inflate(R.layout.confirm_key_layout, null);
                ((TextView) layout.findViewById(R.id.confirmKeyFingerprint)).setText(fingerprint);
                builder.setView(layout);

                // Send back to the server if the key has been confirmed or rejected
                builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        Log.d(TAG, "Confirmed key: " + fingerprint);
                        LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", true));
                    }
                });
                builder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        Log.d(TAG, "Rejected key: " + fingerprint);
                        LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", false));
                    }
                });

                builder.setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                        Log.d(TAG, "Dismissed key dialog: " + fingerprint);
                        LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", false));
                    }
                });

                final AlertDialog dialog = builder.create();
                dialog.show();

                // Dismiss the dialog if the server lost connection to this client
                LocalBroadcastManager.getInstance(context).registerReceiver(new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        LocalBroadcastManager.getInstance(context).unregisterReceiver(this);
                        dialog.dismiss();
                    }
                }, new IntentFilter("MainActivity.dismissConfirmKeyDialog:" + fingerprint));
            }
        }, new IntentFilter("MainActivity.showConfirmKeyDialog"));

    }

    private void startServer() {
        Log.d(TAG, "Starting server...");
        startStopButton.setText(getString(R.string.stopServer));

        Intent serviceIntent = new Intent(this, ServerService.class);
        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(serviceIntent);
        else
            startService(serviceIntent);
    }

    private void stopServer() {
        Log.d(TAG, "Stopping server...");
        LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent("ServerService.stop"));
    }
}
