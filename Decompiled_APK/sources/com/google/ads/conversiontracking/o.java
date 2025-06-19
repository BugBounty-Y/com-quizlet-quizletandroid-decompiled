package com.google.ads.conversiontracking;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.util.Log;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Locale;

/* loaded from: classes2.dex */
public class o {
    public static final String c;
    public final n a;
    public final Object b = new Object();

    static {
        Locale locale = Locale.US;
        c = "CREATE TABLE IF NOT EXISTS conversiontracking ( conversion_ping_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, string_url TEXT NOT NULL, preference_key TEXT, is_repeatable INTEGER, parameter_is_null INTEGER, preference_name TEXT, record_time INTEGER, retry_count INTEGER,last_retry_time INTEGER);";
    }

    public o(Context context) {
        this.a = new n(context, "google_conversion_tracking.db", null, 5);
    }

    public static h b(Cursor cursor) {
        boolean z;
        String str;
        boolean z2;
        int i = cursor.getInt(7);
        String string = cursor.getString(1);
        if (i > 0) {
            string = Uri.parse(string).buildUpon().appendQueryParameter("retry", Integer.toString(i)).build().toString();
        }
        String str2 = string;
        long j = cursor.getLong(0);
        String string2 = cursor.getString(2);
        if (cursor.getInt(3) > 0) {
            z = false;
            str = string2;
            z2 = true;
        } else {
            z = false;
            str = string2;
            z2 = false;
        }
        if (cursor.getInt(4) > 0) {
            z = true;
        }
        return new h(j, str2, str, z2, z, cursor.getString(5), cursor.getLong(6), i);
    }

    public final SQLiteDatabase a() {
        try {
            return this.a.getWritableDatabase();
        } catch (SQLiteException unused) {
            Log.w("GoogleConversionReporter", "Error opening writable conversion tracking database");
            return null;
        }
    }

    public final LinkedList c() {
        synchronized (this.b) {
            LinkedList linkedList = new LinkedList();
            SQLiteDatabase sQLiteDatabaseA = a();
            if (sQLiteDatabaseA == null) {
                return linkedList;
            }
            Cursor cursorQuery = null;
            try {
                try {
                    cursorQuery = sQLiteDatabaseA.query("conversiontracking", null, null, null, null, null, "last_retry_time ASC", String.valueOf(100L));
                    if (cursorQuery.moveToFirst()) {
                        do {
                            linkedList.add(b(cursorQuery));
                        } while (cursorQuery.moveToNext());
                    }
                } catch (SQLiteException e) {
                    String strValueOf = String.valueOf(e.getMessage());
                    Log.w("GoogleConversionReporter", strValueOf.length() != 0 ? "Error extracing ping Info: ".concat(strValueOf) : new String("Error extracing ping Info: "));
                    if (cursorQuery != null) {
                    }
                }
                cursorQuery.close();
                return linkedList;
            } catch (Throwable th) {
                if (cursorQuery != null) {
                    cursorQuery.close();
                }
                throw th;
            }
        }
    }

    public final void d(h hVar) {
        if (hVar == null) {
            return;
        }
        synchronized (this.b) {
            try {
                SQLiteDatabase sQLiteDatabaseA = a();
                if (sQLiteDatabaseA == null) {
                    return;
                }
                Locale locale = Locale.US;
                sQLiteDatabaseA.delete("conversiontracking", "conversion_ping_id = " + hVar.h, null);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void e() {
        synchronized (this.b) {
            try {
                SQLiteDatabase sQLiteDatabaseA = a();
                if (sQLiteDatabaseA == null) {
                    return;
                }
                Locale locale = Locale.US;
                HashMap map = r.a;
                sQLiteDatabaseA.delete("conversiontracking", "(retry_count > 9000) or (record_time < " + (System.currentTimeMillis() - 43200000) + " and retry_count > 0)", null);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void f(h hVar) {
        synchronized (this.b) {
            try {
                SQLiteDatabase sQLiteDatabaseA = a();
                if (sQLiteDatabaseA == null) {
                    return;
                }
                ContentValues contentValues = new ContentValues();
                contentValues.put("string_url", hVar.g);
                contentValues.put("preference_key", hVar.f);
                contentValues.put("is_repeatable", Integer.valueOf(hVar.b ? 1 : 0));
                contentValues.put("parameter_is_null", Integer.valueOf(hVar.a ? 1 : 0));
                contentValues.put("preference_name", hVar.e);
                contentValues.put("record_time", Long.valueOf(hVar.d));
                contentValues.put("retry_count", (Integer) 0);
                contentValues.put("last_retry_time", Long.valueOf(hVar.d));
                hVar.h = sQLiteDatabaseA.insert("conversiontracking", null, contentValues);
                e();
                if (g() > 20000) {
                    i();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final int g() {
        synchronized (this.b) {
            SQLiteDatabase sQLiteDatabaseA = a();
            if (sQLiteDatabaseA == null) {
                return 0;
            }
            Cursor cursorRawQuery = null;
            try {
                try {
                    cursorRawQuery = sQLiteDatabaseA.rawQuery("select count(*) from conversiontracking", null);
                    if (cursorRawQuery.moveToFirst()) {
                        int i = cursorRawQuery.getInt(0);
                        cursorRawQuery.close();
                        return i;
                    }
                } catch (SQLiteException e) {
                    String strValueOf = String.valueOf(e.getMessage());
                    Log.w("GoogleConversionReporter", strValueOf.length() != 0 ? "Error getting record count".concat(strValueOf) : new String("Error getting record count"));
                    if (cursorRawQuery != null) {
                    }
                }
                cursorRawQuery.close();
                return 0;
            } catch (Throwable th) {
                if (cursorRawQuery != null) {
                    cursorRawQuery.close();
                }
                throw th;
            }
        }
    }

    public final void h(h hVar) {
        synchronized (this.b) {
            try {
                SQLiteDatabase sQLiteDatabaseA = a();
                if (sQLiteDatabaseA == null) {
                    return;
                }
                ContentValues contentValues = new ContentValues();
                HashMap map = r.a;
                contentValues.put("last_retry_time", Long.valueOf(System.currentTimeMillis()));
                contentValues.put("retry_count", Integer.valueOf(hVar.c + 1));
                Locale locale = Locale.US;
                sQLiteDatabaseA.update("conversiontracking", contentValues, "conversion_ping_id = " + hVar.h, null);
                e();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void i() {
        synchronized (this.b) {
            SQLiteDatabase sQLiteDatabaseA = a();
            if (sQLiteDatabaseA == null) {
                return;
            }
            Cursor cursorQuery = null;
            try {
                try {
                    cursorQuery = sQLiteDatabaseA.query("conversiontracking", null, null, null, null, null, "record_time ASC", "1");
                    if (cursorQuery != null && cursorQuery.moveToFirst()) {
                        d(b(cursorQuery));
                    }
                } catch (SQLiteException e) {
                    String strValueOf = String.valueOf(e.getMessage());
                    Log.w("GoogleConversionReporter", strValueOf.length() != 0 ? "Error remove oldest record".concat(strValueOf) : new String("Error remove oldest record"));
                    if (cursorQuery != null) {
                    }
                }
            } finally {
                if (cursorQuery != null) {
                    cursorQuery.close();
                }
            }
        }
    }
}
