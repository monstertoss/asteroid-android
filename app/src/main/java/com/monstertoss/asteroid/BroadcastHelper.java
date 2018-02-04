package com.monstertoss.asteroid;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Log;

import java.util.HashMap;

// This is a helper class that keeps track of all BroadcastReceivers for a proper cleanup
public class BroadcastHelper {
    private static final String TAG = "BroadcastHelper";

    private HashMap<String, BroadcastReceiver> receivers;

    private Context context;

    // Store the application context
    public BroadcastHelper(Context context) {
        this.context = context.getApplicationContext();
        this.receivers = new HashMap<>();
    }

    // Register a broadcast listener and add it to the list to keep track
    public void addBroadcastListener(BroadcastReceiver receiver, String action) {
        if (receivers.containsKey(action)) {
            Log.e(TAG, "Called addBroadcastListener with action already existing: " + action);
        } else {
            receivers.put(action, receiver);
            LocalBroadcastManager.getInstance(context).registerReceiver(receiver, new IntentFilter(action));
        }
    }

    // Unregister a broadcast listener and remove it from our list
    public void removeBroadcastListener(String action) {
        BroadcastReceiver receiver = receivers.get(action);

        if (receiver == null) {
            Log.e(TAG, "Called removeBroadcastListener with action not existing: " + action);
        } else {
            LocalBroadcastManager.getInstance(context).unregisterReceiver(receiver);
            receivers.remove(action);
        }
    }

    // Unregister everything on our list
    public void removeAllBroadcastListeners() {
        for(String action : receivers.keySet()) {
            removeBroadcastListener(action);
        }
    }

    // Send a Broadcast with just a name
    public void sendBroadcast(String action) {
        _sendBroadcast(new Intent(action));
    }

    // Send a broadcast with a name and extras
    public void sendBroadcast(String action, Bundle extras) {
        _sendBroadcast(new Intent(action).putExtras(extras));
    }

    // Send a broadcast with the given Intent
    public void sendBroadcast(Intent intent) {
        _sendBroadcast(intent);
    }

    // Do the actual broadcast sending
    private void _sendBroadcast(Intent intent) {
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
    }

}