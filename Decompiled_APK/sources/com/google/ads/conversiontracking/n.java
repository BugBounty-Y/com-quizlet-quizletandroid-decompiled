package com.google.ads.conversiontracking;

import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

/* loaded from: classes2.dex */
public final class n extends SQLiteOpenHelper {
    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase) throws SQLException {
        sQLiteDatabase.execSQL(o.c);
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) throws SQLException {
        StringBuilder sb = new StringBuilder(64);
        sb.append("Database updated from version ");
        sb.append(i);
        sb.append(" to version ");
        sb.append(i2);
        Log.i("GoogleConversionReporter", sb.toString());
        sQLiteDatabase.execSQL("DROP TABLE IF EXISTS conversiontracking");
        onCreate(sQLiteDatabase);
    }
}
