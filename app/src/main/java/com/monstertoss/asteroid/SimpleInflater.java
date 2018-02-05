package com.monstertoss.asteroid;

import android.content.ContentValues;
import android.content.Context;

/**
 * Simple inflater that assumes a string resource has a "%s" that will be
 * filled from the given column.
 */
public class SimpleInflater {
    private final int mStringRes;
    private final String mColumnName;

    public SimpleInflater(int stringRes) {
        this(stringRes, null);
    }

    public SimpleInflater(String columnName) {
        this(-1, columnName);
    }

    public SimpleInflater(int stringRes, String columnName) {
        mStringRes = stringRes;
        mColumnName = columnName;
    }

    public CharSequence inflateUsing(Context context, ContentValues values) {
        final boolean validColumn = values.containsKey(mColumnName);
        final boolean validString = mStringRes > 0;

        final CharSequence stringValue = validString ? context.getText(mStringRes) : null;
        final CharSequence columnValue = validColumn ? values.getAsString(mColumnName) : null;

        if (validString && validColumn) {
            return String.format(stringValue.toString(), columnValue);
        } else if (validString) {
            return stringValue;
        } else if (validColumn) {
            return columnValue;
        } else {
            return null;
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + " mStringRes=" + mStringRes + " mColumnName" + mColumnName;
    }
}
