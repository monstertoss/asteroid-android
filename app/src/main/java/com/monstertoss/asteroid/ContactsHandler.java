package com.monstertoss.asteroid;

import android.database.Cursor;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static com.monstertoss.asteroid.MessageOpcode.*;
import static com.monstertoss.asteroid.SocketState.*;

class ContactsHandler {
    private static final String TAG = "ContactsHandler";

    static void HandleRequestContacts(final ServerService context, Packet packet, final SocketData data) {
        // Allow this only if we are authorized
        if (data.state != AUTHORIZED) {
            Log.d(TAG, "[" + data.id + "] Closing: Got C2S_REQUEST_CONTACTS but are not authorized");
            data.close();
            return;
        }

        new ContactsLoader(context, new ContactsLoader.OnContactsLoaded() {
            @Override
            public void onLoadComplete(Cursor cursor) {
                sendContacts(context, data, cursor);
            }
        });
    }

    static void sendContacts(ServerService context, SocketData data, Cursor cursor) {
        Log.d(TAG, "[" + data.id + "] Loaded " + cursor.getCount() + " Contacts");
        try {
            JSONObject payload = new JSONObject();
            JSONArray array = ContactsLoader.CursorToJSON(cursor);
            payload.put("contacts", array);
            data.send(S2C_RESPONSE_CONTACTS, payload);
        } catch(JSONException e) {}
    }

}
