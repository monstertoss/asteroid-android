package com.monstertoss.asteroid;

import android.Manifest;
import android.app.ActivityManager;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    private static String TAG = "MainActivity";

    private Button startStopButton;

    private BroadcastHelper broadcasts;

    // Helper method to check if the server is running
    private boolean isServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        try {
            for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
                if (serviceClass.getName().equals(service.service.getClassName())) {
                    return true;
                }
            }
        } catch(NullPointerException e) {
            return false;
        }
        return false;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Initialize our Broadcast Helper
        broadcasts = new BroadcastHelper(this);

        // Create notification channel
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager mNotificationManager = (NotificationManager) getApplicationContext().getSystemService(Context.NOTIFICATION_SERVICE);
            CharSequence name = getString(R.string.notificationChannel);
            int importance = NotificationManager.IMPORTANCE_LOW;
            NotificationChannel mChannel = new NotificationChannel(getPackageName(), name, importance);
            try {
                mNotificationManager.createNotificationChannel(mChannel);
            } catch(NullPointerException e) {}
        }

        startStopButton = findViewById(R.id.startStopButton);

        // Execute start stop based on whether the server is running
        startStopButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (isServiceRunning(ServerService.class)) {
                    stopServer();
                } else {
                    startServer();
                }
            }
        });
        startStopButton.setText(getString(isServiceRunning(ServerService.class) ? R.string.stopServer : R.string.startServer));

        // Broadcast receiver for when the server has stopped. This is used to set the UI in the correct state
        broadcasts.addBroadcastListener(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.d(TAG, "Received server stop");
                startStopButton.setText(getString(R.string.startServer));
            }
        }, "MainActivity.stopped");

        // Broadcast receiver that is called when an unknown key is sent to the server.
        // It is used to show a popup to confirm the public key.
        broadcasts.addBroadcastListener(new BroadcastReceiver() {
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
                        broadcasts.sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", true));
                    }
                });
                builder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int id) {
                        Log.d(TAG, "Rejected key: " + fingerprint);
                        broadcasts.sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", false));
                    }
                });

                builder.setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                        Log.d(TAG, "Dismissed key dialog: " + fingerprint);
                        broadcasts.sendBroadcast(new Intent("ServerService.confirmKeyDialogResponse:" + fingerprint).putExtra("confirmed", false));
                    }
                });

                final AlertDialog dialog = builder.create();
                dialog.show();

                // Dismiss the dialog if the server lost connection to this client
                broadcasts.addBroadcastListener(new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        broadcasts.removeBroadcastListener("MainActivity.dismissConfirmKeyDialog:" + fingerprint);
                        if (dialog.isShowing())
                            dialog.dismiss();
                    }
                }, "MainActivity.dismissConfirmKeyDialog:" + fingerprint);
            }
        }, "MainActivity.showConfirmKeyDialog");

        // Make sure we have the contact permissions
        requestPermissionsIfNotThere();
    }

    // Called right before our activity is destroyed
    @Override
    public void onDestroy() {
        // Remove all broadcast listeners
        broadcasts.removeAllBroadcastListeners();

        super.onDestroy();
    }

    // Called after the user granted or denied our permission
    @Override
    public void onRequestPermissionsResult(int requestCode, String permissions[], int[] grantResults) {
        if (permissions.length == 0) {
            return;
        }

        // Check if we have all permissions we asked for (we asked for all we need)
        boolean grantedEverything = true;
        if (grantResults.length > 0) {
            for (int grantResult : grantResults) {
                if (grantResult != PackageManager.PERMISSION_GRANTED) {
                    grantedEverything = false;
                    break;
                }
            }
        }

        // If we don't have all permissions
        if (!grantedEverything) {
            boolean neverAskAgain = false;
            for (String permission : permissions) {
                if (ActivityCompat.shouldShowRequestPermissionRationale(this, permission)) {
                    // Permission denied, boo!

                    // But we need it. Request again :)
                    requestPermissionsIfNotThere();
                } else {
                    if (ActivityCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED) {
                        // permission was granted, yay!

                        // Doing nothing :)
                    } else {
                        // Permission denied, but with never ask again.
                        neverAskAgain = true;
                    }
                }
            }

            if (neverAskAgain) {
                // Show a fancy dialog if never ask again
                new AlertDialog.Builder(this)
                        .setTitle(R.string.noPermissionsTitle)
                        .setMessage(R.string.noPermissionsDescription)
                        .setPositiveButton(R.string.settings, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", getPackageName(), null));
                                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                startActivity(intent);
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                            }
                        })
                        .setCancelable(false)
                        .create()
                        .show();
            }
        } else {
            requestPermissionsIfNotThere();
        }
    }

    private boolean requestPermissionsIfNotThere() {
        boolean readContacts = ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED;
        boolean writeContacts = ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_CONTACTS) == PackageManager.PERMISSION_GRANTED;

        if (!readContacts || !writeContacts)
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.READ_CONTACTS, Manifest.permission.WRITE_CONTACTS}, 0);

        return readContacts && writeContacts;
    }

    private void startServer() {
        if (!requestPermissionsIfNotThere()) {
            Log.d(TAG, "Tried to start server but missing permission(s)");
            return;
        }

        Log.d(TAG, "Starting server...");
        startStopButton.setText(getString(R.string.stopServer));

        Intent serviceIntent = new Intent(this, ServerService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(serviceIntent);
        else
            startService(serviceIntent);
    }

    private void stopServer() {
        Log.d(TAG, "Stopping server...");
        broadcasts.sendBroadcast("ServerService.stop");
    }
}