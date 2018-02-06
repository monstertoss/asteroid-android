package com.monstertoss.asteroid;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.database.Cursor;

import android.provider.ContactsContract.*;
import android.support.annotation.XmlRes;
import android.util.AttributeSet;
import android.util.Base64;
import android.util.Log;
import android.util.Xml;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
        Cursor contacts = context.getContentResolver().query(Contacts.CONTENT_URI, null, null, null, Contacts.DISPLAY_NAME_PRIMARY + " COLLATE LOCALIZED ASC");
        Cursor rawContacts = context.getContentResolver().query(RawContacts.CONTENT_URI, null, null, null, RawContacts.CONTACT_ID + " ASC");
        Cursor data = context.getContentResolver().query(Data.CONTENT_URI, null, null, null, Data.RAW_CONTACT_ID + " ASC");

        JSONObject thirdPartyData = LoadThirdPartyData(context);

        callback.onLoadComplete(contacts, rawContacts, data, thirdPartyData);

        contacts.close();
        rawContacts.close();
        data.close();
    }

    public interface OnContactsLoaded {
        public void onLoadComplete(Cursor contacts, Cursor rawcontacts, Cursor data, JSONObject thirdPartyData);
    }

    static JSONArray CursorToJSON(Cursor cursor) {
        return CursorToJSON(cursor, false);
    }

    static JSONArray CursorToJSON(Cursor cursor, boolean preserveCursor) {
        int position = cursor.getPosition();
        JSONArray array = new JSONArray();

        if (!cursor.isBeforeFirst())
            cursor.moveToFirst();

        while (cursor.moveToNext()) {
            JSONObject object = new JSONObject();
            for (String column : cursor.getColumnNames()) {
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
                } catch (JSONException e) {
                }
            }
            array.put(object);
        }

        if (preserveCursor)
            cursor.moveToPosition(position);

        return array;
    }

    // The following is a simplified excerpt of the LineageOS source that handles third party mimetypes
    // The original source code can be found under the link below and in the files linked there
    //
    // https://github.com/LineageOS/android_packages_apps_ContactsCommon/blob/cm-14.1/src/com/android/contacts/common/model/account/ExternalAccountType.java

    private static final String SYNC_META_DATA = "android.content.SyncAdapter";
    private static final String[] METADATA_CONTACTS_NAMES = new String[]{
            "android.provider.ALTERNATE_CONTACTS_STRUCTURE",
            "android.provider.CONTACTS_STRUCTURE"
    };

    private static final String TAG_SYNC_ADAPTER = "sync-adapter";
    private static final String TAG_CONTACTS_SOURCE_LEGACY = "ContactsSource";
    private static final String TAG_CONTACTS_ACCOUNT_TYPE = "ContactsAccountType";
    private static final String TAG_CONTACTS_DATA_KIND = "ContactsDataKind";
    private static final String TAG_EDIT_SCHEMA = "EditSchema";

    private static final String ATTR_ACCOUNT_TYPE = "accountType";

    public static JSONObject LoadThirdPartyData(Context context) {
        JSONObject thirdPartyData = new JSONObject();

        PackageManager pm = context.getPackageManager();
        Intent intent = new Intent(SYNC_META_DATA);
        List<ResolveInfo> intentServices = pm.queryIntentServices(intent, PackageManager.GET_META_DATA);

        if (intentServices == null)
            return thirdPartyData;

        for (ResolveInfo resolveInfo : intentServices) {
            ServiceInfo serviceInfo = resolveInfo.serviceInfo;
            if (serviceInfo == null)
                continue;

            for (String metadataName : METADATA_CONTACTS_NAMES) {
                XmlResourceParser parser = serviceInfo.loadXmlMetaData(pm, metadataName);
                if (parser == null)
                    continue;

                XmlResourceParser syncParser = serviceInfo.loadXmlMetaData(pm, SYNC_META_DATA);
                if(syncParser == null)
                    continue;

                try {
                    Log.v(TAG, String.format("Metadata loaded from: %s, %s, %s", serviceInfo.packageName, serviceInfo.name, metadataName));

                    JSONObject appData = new JSONObject();
                    appData.put("package_name", serviceInfo.packageName);
                    appData.put("account_type", getAccountTypeFromSyncMetaData(context, syncParser, serviceInfo.packageName));

                    JSONObject dataKinds = new JSONObject();

                    AttributeSet attrs = Xml.asAttributeSet(parser);

                    int type;
                    while ((type = parser.next()) != XmlPullParser.START_TAG && type != XmlPullParser.END_DOCUMENT) {
                        // Drain comments and whitespace
                    }

                    if (type != XmlPullParser.START_TAG) {
                        Log.w(TAG, "No start tag found");
                        continue;
                    }

                    String rootTag = parser.getName();
                    if (!TAG_CONTACTS_ACCOUNT_TYPE.equals(rootTag) && !TAG_CONTACTS_SOURCE_LEGACY.equals(rootTag)) {
                        Log.w(TAG, "Top level element must be " + TAG_CONTACTS_ACCOUNT_TYPE + ", not " + rootTag);
                        continue;
                    }

                    // Parse all children kinds
                    final int startDepth = parser.getDepth();
                    while (((type = parser.next()) != XmlPullParser.END_TAG || parser.getDepth() > startDepth) && type != XmlPullParser.END_DOCUMENT) {

                        if (type != XmlPullParser.START_TAG || parser.getDepth() != startDepth + 1) {
                            continue; // Not a direct child tag
                        }

                        String tag = parser.getName();
                        if (TAG_EDIT_SCHEMA.equals(tag)) {
                            appData.put("has_edit_schema", true);
                        } else if (TAG_CONTACTS_DATA_KIND.equals(tag)) {
                            TypedArray a = context.obtainStyledAttributes(attrs, R.styleable.ContactsDataKind);

                            String mimetype = a.getString(R.styleable.ContactsDataKind_android_mimeType);
                            String summaryColumn = a.getString(R.styleable.ContactsDataKind_android_summaryColumn);
                            String detailColumn = a.getString(R.styleable.ContactsDataKind_android_detailColumn);

                            try {
                                JSONObject dataKind = new JSONObject();
                                dataKind.put("mimetype", mimetype);
                                dataKind.put("summaryColumn", summaryColumn);
                                dataKind.put("detailColumn", detailColumn);
                                dataKinds.put(mimetype, dataKind);
                            } catch (JSONException e) {
                            }

                            a.recycle();
                        }
                    }
                    appData.put("data_kinds", dataKinds);
                    if(!appData.has("has_edit_schema"))
                        appData.put("has_edit_schema", false);
                    thirdPartyData.put(serviceInfo.packageName, appData);
                } catch (XmlPullParserException | IOException | JSONException | PackageManager.NameNotFoundException e) {
                }
            }
        }

        return thirdPartyData;
    }

    private static String getAccountTypeFromSyncMetaData(Context context, XmlPullParser parser, String packageName) throws XmlPullParserException, IOException, PackageManager.NameNotFoundException {
        String accountType = "";

        AttributeSet attrs = Xml.asAttributeSet(parser);

        int type;
        while ((type = parser.next()) != XmlPullParser.START_TAG && type != XmlPullParser.END_DOCUMENT) {
            // Drain comments and whitespace
        }

        if (type != XmlPullParser.START_TAG) {
            Log.w(TAG, "No start tag found");
            throw new XmlPullParserException("No start tag found");
        }

        String rootTag = parser.getName();
        if (!TAG_SYNC_ADAPTER.equals(rootTag)) {
            Log.w(TAG, "Top level element must be " + TAG_SYNC_ADAPTER + ", not " + rootTag);
            throw new XmlPullParserException("Top level element must be " + TAG_SYNC_ADAPTER + ", not " + rootTag);
        }

        int attributeCount = parser.getAttributeCount();
        for (int i = 0; i < attributeCount; i++) {
            if(ATTR_ACCOUNT_TYPE.equals(parser.getAttributeName(i)))
                accountType = parser.getAttributeValue(i);
        }

        if(accountType.startsWith("@")) { // If string is a reference to another string, switch context and follow reference
            Context foreignContext = context.createPackageContext(packageName, 0);
            accountType = foreignContext.getString(Integer.parseInt(accountType.substring(1)));
        }
        return accountType;
    }
}