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
            public void onLoadComplete(Cursor contacts, Cursor rawContacts, Cursor contactsData, JSONArray dataKinds) {
                sendContacts(context, data, contacts, rawContacts, contactsData, dataKinds);
            }
        });
    }

    static void sendContacts(ServerService context, SocketData data, Cursor contacts, Cursor rawContacts, Cursor contactsData, JSONArray dataKinds) {
        Log.d(TAG, "[" + data.id + "] Loaded " + dataKinds.length() + " DataKinds " + contacts.getCount() + " Contacts " + rawContacts.getCount() + " Raw Contacts " + contactsData.getCount() + " Datasets");
        try {
            JSONObject payload = new JSONObject();
            payload.put("contacts", ContactsLoader.CursorToJSON(contacts));
            payload.put("rawContacts", ContactsLoader.CursorToJSON(rawContacts));
            payload.put("data", ContactsLoader.CursorToJSON(contactsData));
            payload.put("dataKinds", dataKinds);
            data.send(S2C_RESPONSE_CONTACTS, payload);
        } catch(JSONException e) {}
    }

}
