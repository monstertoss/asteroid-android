package com.monstertoss.asteroid;

import android.content.Context;
import android.content.CursorLoader;
import android.content.Loader;
import android.database.Cursor;
import android.net.Uri;

import android.provider.ContactsContract;
import android.provider.ContactsContract.Contacts;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ContactsLoader {

    static String TAG = "ContactsLoader";

    Context context;
    OnContactsLoaded callback;

    ContactsLoader(Context context, OnContactsLoaded callback) {
        this.context = context;
        this.callback = callback;

        fetchContacts();
    }

    private void fetchContacts() {
        Cursor cursor = context.getContentResolver().query(ContactsContract.Data.CONTENT_URI, null, null, null, Contacts.DISPLAY_NAME_PRIMARY + " COLLATE LOCALIZED ASC");                       // The sort order for the returned rows

        callback.onLoadComplete(cursor);
        cursor.close();
    }

    public interface OnContactsLoaded {
        public void onLoadComplete(Cursor cursor);
    }

    static JSONArray CursorToJSON(Cursor cursor) {
        return CursorToJSON(cursor, false);
    }
    static JSONArray CursorToJSON(Cursor cursor, boolean preserveCursor) {
        int position = cursor.getPosition();
        JSONArray array = new JSONArray();

        if(!cursor.isBeforeFirst())
            cursor.moveToFirst();

        while (cursor.moveToNext()) {
            JSONObject object = new JSONObject();
            for(String column : cursor.getColumnNames()) {
                try {
                    int index = cursor.getColumnIndex(column);
                    int type = cursor.getType(index);
                    switch (type) {
                        case Cursor.FIELD_TYPE_NULL:
                            object.put(column, JSONObject.NULL);
                            break;

                        case Cursor.FIELD_TYPE_INTEGER:
                            object.put(column, cursor.getInt(index));
                            break;

                        case Cursor.FIELD_TYPE_FLOAT:
                            object.put(column, cursor.getFloat(index));
                            break;

                        case Cursor.FIELD_TYPE_STRING:
                            object.put(column, cursor.getString(index));
                            break;

                        case Cursor.FIELD_TYPE_BLOB:
                            object.put(column, Base64.encodeToString(cursor.getBlob(index), Base64.NO_WRAP));
                            break;
                    }
                } catch(JSONException e) {}
            }
            array.put(object);
        }

        if(preserveCursor)
            cursor.moveToPosition(position);

        return array;
    }
}