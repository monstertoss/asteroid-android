package com.monstertoss.asteroid;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.provider.BaseColumns;

// Database helper for storing client public keys
// See https://developer.android.com/training/basics/data-storage/databases.html for more help
public class KeyDatabase extends SQLiteOpenHelper {

    public static class KeyEntry implements BaseColumns {
        public static final String TABLE_NAME = "publickeys";

        public static final String KEY_TITLE = "key";
        public static final String FINGERPRINT_TITLE = "fingerprint";
    }

    private static final String SQL_CREATE_ENTRIES = "CREATE TABLE " + KeyEntry.TABLE_NAME + " (" + KeyEntry._ID + " INTEGER PRIMARY KEY," + KeyEntry.KEY_TITLE + " TEXT," + KeyEntry.FINGERPRINT_TITLE + " VARCHAR(255))";

    private static final String SQL_DELETE_ENTRIES = "DROP TABLE IF EXISTS " + KeyEntry.TABLE_NAME;

    public static final int DATABASE_VERSION = 2;
    public static final String DATABASE_NAME = "PublicKeys.db";

    public KeyDatabase(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    public void onCreate(SQLiteDatabase db) {
        db.execSQL(SQL_CREATE_ENTRIES);
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // This database is only a cache for online data, so its upgrade policy is
        // to simply to discard the data and start over
        RecreateDatabase(db);
    }

    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        RecreateDatabase(db);
    }

    private boolean DoesExist(String key, String value) {
        SQLiteDatabase db = getReadableDatabase();

        String[] projection = {KeyEntry._ID};

        String selection = key + " = ?";
        String[] selectionArgs = {value};

        Cursor cursor = db.query(KeyEntry.TABLE_NAME, projection, selection, selectionArgs, null, null, null);
        boolean ret = cursor.getCount() > 0;
        cursor.close();
        return ret;
    }

    public boolean DoesKeyExist(String key) {
        return DoesExist(KeyEntry.KEY_TITLE, key);
    }

    public boolean DoesFingerprintExist(String fingerprint) {
        return DoesExist(KeyEntry.FINGERPRINT_TITLE, fingerprint);
    }

    public void PutKey(String key, String fingerprint) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(KeyEntry.KEY_TITLE, key);
        values.put(KeyEntry.FINGERPRINT_TITLE, fingerprint);

        long rowID = db.insert(KeyEntry.TABLE_NAME, null, values);
    }

    private void Delete(String key, String value) {
        SQLiteDatabase db = getWritableDatabase();
        String selection = key + " = ?";
        String[] selectionArgs = {value};
        db.delete(KeyEntry.TABLE_NAME, selection, selectionArgs);
    }

    public void DeleteKey(String key) {
        if(!DoesKeyExist(key))
            return;

        Delete(KeyEntry.KEY_TITLE, key);
    }

    public void DeleteFingerprint(String fingerprint) {
        if(!DoesFingerprintExist(fingerprint))
            return;

        Delete(KeyEntry.FINGERPRINT_TITLE, fingerprint);
    }

    private void RecreateDatabase(SQLiteDatabase db) {
        db.execSQL(SQL_DELETE_ENTRIES);
        db.execSQL(SQL_CREATE_ENTRIES);
    }

    public void DeleteAllKeys() {
        RecreateDatabase(getWritableDatabase());
    }
}
