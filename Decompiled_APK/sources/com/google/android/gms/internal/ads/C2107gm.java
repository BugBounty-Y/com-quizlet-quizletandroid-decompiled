package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import com.amazon.device.ads.DTBMetricsConfiguration;

/* renamed from: com.google.android.gms.internal.ads.gm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2107gm extends Hs {
    public final Context a;
    public final C2227jd b;

    public C2107gm(Context context, C2227jd c2227jd) {
        super(context, "AdMobOfflineBufferedPings.db", ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r8)).intValue());
        this.a = context;
        this.b = c2227jd;
    }

    public static void f(SQLiteDatabase sQLiteDatabase, com.google.android.gms.ads.internal.util.client.k kVar) {
        SQLiteDatabase sQLiteDatabase2;
        String str;
        sQLiteDatabase.beginTransaction();
        try {
            sQLiteDatabase2 = sQLiteDatabase;
            try {
                Cursor cursorQuery = sQLiteDatabase2.query("offline_buffered_pings", new String[]{"timestamp", DTBMetricsConfiguration.APSMETRICS_URL}, "event_state = 1", null, null, null, "timestamp ASC", null);
                int count = cursorQuery.getCount();
                String[] strArr = new String[count];
                int i = 0;
                while (cursorQuery.moveToNext()) {
                    int columnIndex = cursorQuery.getColumnIndex("timestamp");
                    int columnIndex2 = cursorQuery.getColumnIndex(DTBMetricsConfiguration.APSMETRICS_URL);
                    if (columnIndex2 != -1) {
                        long j = cursorQuery.getLong(columnIndex);
                        String string = cursorQuery.getString(columnIndex2);
                        if (string == null) {
                            str = "";
                        } else {
                            Uri uri = Uri.parse(string);
                            com.google.android.gms.ads.internal.j.C.k.getClass();
                            long jCurrentTimeMillis = System.currentTimeMillis() - j;
                            String encodedQuery = uri.getEncodedQuery();
                            Uri.Builder builderClearQuery = uri.buildUpon().clearQuery();
                            builderClearQuery.appendQueryParameter("bd", Long.toString(jCurrentTimeMillis));
                            str = String.valueOf(builderClearQuery.build()) + "&" + encodedQuery;
                        }
                        strArr[i] = str;
                    }
                    i++;
                }
                cursorQuery.close();
                sQLiteDatabase2.delete("offline_buffered_pings", "event_state = ?", new String[]{Integer.toString(1)});
                sQLiteDatabase2.setTransactionSuccessful();
                sQLiteDatabase2.endTransaction();
                for (int i2 = 0; i2 < count; i2++) {
                    kVar.zza(strArr[i2]);
                }
            } catch (Throwable th) {
                th = th;
                Throwable th2 = th;
                sQLiteDatabase2.endTransaction();
                throw th2;
            }
        } catch (Throwable th3) {
            th = th3;
            sQLiteDatabase2 = sQLiteDatabase;
        }
    }

    public final void a(String str) {
        d(new C2332lw(str, 6));
    }

    public final void d(Gq gq) {
        Q4 q4 = new Q4(this, 6);
        C2227jd c2227jd = this.b;
        com.google.common.util.concurrent.e eVarD = c2227jd.d(q4);
        eVarD.a(new Qv(0, eVarD, new Os(gq, 23)), c2227jd);
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase) throws SQLException {
        sQLiteDatabase.execSQL("CREATE TABLE offline_buffered_pings (timestamp INTEGER PRIMARY_KEY, gws_query_id TEXT, url TEXT, event_state INTEGER)");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onDowngrade(SQLiteDatabase sQLiteDatabase, int i, int i2) throws SQLException {
        sQLiteDatabase.execSQL("DROP TABLE IF EXISTS offline_buffered_pings");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) throws SQLException {
        sQLiteDatabase.execSQL("DROP TABLE IF EXISTS offline_buffered_pings");
    }
}
