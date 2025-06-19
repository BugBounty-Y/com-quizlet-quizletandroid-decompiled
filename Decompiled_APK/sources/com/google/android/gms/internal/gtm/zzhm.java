package com.google.android.gms.internal.gtm;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteConstraintException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.text.TextUtils;
import com.google.android.gms.common.util.a;
import com.google.android.gms.common.util.b;
import com.google.android.gms.common.util.c;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
final class zzhm implements zzha {
    private static final String zza = "CREATE TABLE IF NOT EXISTS gtm_hit_unique_ids ('hit_unique_id' TEXT UNIQUE);";
    private static final String zzb = "CREATE TABLE IF NOT EXISTS gtm_hits ( 'hit_id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 'hit_time' INTEGER NOT NULL, 'hit_url' TEXT NOT NULL, 'hit_first_send_time' INTEGER NOT NULL, 'hit_method' TEXT NOT NULL, 'hit_unique_id' TEXT UNIQUE, 'hit_headers' TEXT, 'hit_body' TEXT);";
    private static final String zzc = "CREATE TRIGGER IF NOT EXISTS save_unique_on_delete DELETE ON gtm_hits FOR EACH ROW WHEN OLD.hit_unique_id NOTNULL BEGIN     INSERT OR IGNORE INTO gtm_hit_unique_ids (hit_unique_id) VALUES (OLD.hit_unique_id); END;";
    private static final String zzd = "CREATE TRIGGER IF NOT EXISTS check_unique_on_insert BEFORE INSERT ON gtm_hits FOR EACH ROW WHEN NEW.hit_unique_id NOT NULL BEGIN     SELECT RAISE(ABORT, 'Duplicate unique ID.')     WHERE EXISTS (SELECT 1 FROM gtm_hit_unique_ids WHERE hit_unique_id = NEW.hit_unique_id); END;";
    private final zzhl zze;
    private volatile zzgs zzf;
    private final Context zzg;
    private final String zzh;
    private long zzi;
    private final a zzj;
    private final int zzk;
    private final zzia zzl;

    public zzhm(zzia zziaVar, Context context) {
        Context applicationContext = context.getApplicationContext();
        this.zzg = applicationContext;
        this.zzh = "gtm_urls.db";
        this.zzl = zziaVar;
        this.zzj = b.a;
        this.zze = new zzhl(this, applicationContext, "gtm_urls.db");
        this.zzf = new zzii(applicationContext, new zzhk(this));
        this.zzi = 0L;
        this.zzk = 2000;
    }

    public static /* bridge */ /* synthetic */ void zzl(zzhm zzhmVar, long j, long j2) {
        SQLiteDatabase sQLiteDatabaseZzn = zzhmVar.zzn("Error opening database for getNumStoredHits.");
        if (sQLiteDatabaseZzn == null) {
            return;
        }
        ContentValues contentValues = new ContentValues();
        contentValues.put("hit_first_send_time", Long.valueOf(j2));
        try {
            sQLiteDatabaseZzn.update("gtm_hits", contentValues, "hit_id=?", new String[]{String.valueOf(j)});
        } catch (SQLiteException e) {
            zzhi.zze("Error setting HIT_FIRST_DISPATCH_TIME for hitId " + j + ": " + e.getMessage());
            zzhmVar.zzo(j);
        }
    }

    private final SQLiteDatabase zzn(String str) {
        try {
            return this.zze.getWritableDatabase();
        } catch (SQLiteException e) {
            Context context = this.zzg;
            zzhi.zzf(str, e);
            c.a(context, e);
            zzhi.zzd("Failed to report crash");
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void zzo(long j) {
        zzm(new String[]{String.valueOf(j)});
    }

    private final void zzp(long j, String str, String str2, String str3, Map map, String str4) throws SQLException {
        SQLiteDatabase sQLiteDatabaseZzn = zzn("Error opening database for putHit");
        if (sQLiteDatabaseZzn == null) {
            return;
        }
        ContentValues contentValues = new ContentValues();
        contentValues.put("hit_time", Long.valueOf(j));
        contentValues.put("hit_url", str);
        contentValues.put("hit_first_send_time", (Integer) 0);
        if (str2 == null) {
            str2 = "GET";
        }
        contentValues.put("hit_method", str2);
        contentValues.put("hit_unique_id", str3);
        contentValues.put("hit_headers", map == null ? null : new JSONObject(map).toString());
        contentValues.put("hit_body", str4);
        try {
            sQLiteDatabaseZzn.insertOrThrow("gtm_hits", null, contentValues);
            zzhi.zzd("Hit stored (url = " + str + ")");
            this.zzl.zza(false);
        } catch (SQLiteConstraintException unused) {
            zzhi.zzd("Hit has already been sent: ".concat(String.valueOf(str)));
        } catch (SQLiteException e) {
            zzhi.zze("Error storing hit: ".concat(String.valueOf(e.getMessage())));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x0260  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x026e  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0277  */
    /* JADX WARN: Removed duplicated region for block: B:164:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01aa A[Catch: all -> 0x0114, TryCatch #10 {all -> 0x0114, blocks: (B:26:0x00ac, B:29:0x00b3, B:31:0x00c0, B:33:0x00e9, B:35:0x00ef, B:36:0x00fe, B:38:0x0104, B:47:0x011d, B:50:0x0162, B:51:0x0164, B:48:0x0127, B:49:0x0147, B:64:0x0182, B:65:0x01a4, B:67:0x01aa, B:72:0x01be), top: B:131:0x00ac }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01c4  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01ff  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0208  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0213  */
    @Override // com.google.android.gms.internal.gtm.zzha
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 635
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.gtm.zzhm.zza():void");
    }

    @Override // com.google.android.gms.internal.gtm.zzha
    public final void zzb(long j, String str, String str2, String str3, Map map, String str4) throws Throwable {
        long jCurrentTimeMillis = this.zzj.currentTimeMillis();
        if (jCurrentTimeMillis > this.zzi + 86400000) {
            this.zzi = jCurrentTimeMillis;
            SQLiteDatabase sQLiteDatabaseZzn = zzn("Error opening database for deleteStaleHits.");
            if (sQLiteDatabaseZzn != null) {
                zzhi.zzd("Removed " + sQLiteDatabaseZzn.delete("gtm_hits", "HIT_TIME < ?", new String[]{Long.toString(this.zzj.currentTimeMillis() - 2592000000L)}) + " stale hits.");
                this.zzl.zza(zzc("gtm_hits") == 0);
            }
        }
        int iZzc = (zzc("gtm_hits") - this.zzk) + 1;
        if (iZzc > 0) {
            ArrayList arrayList = new ArrayList();
            SQLiteDatabase sQLiteDatabaseZzn2 = zzn("Error opening database for peekHitIds.");
            if (sQLiteDatabaseZzn2 != null) {
                Cursor cursorQuery = null;
                try {
                    try {
                        cursorQuery = sQLiteDatabaseZzn2.query("gtm_hits", new String[]{"hit_id"}, null, null, null, null, "hit_id ASC", Integer.toString(iZzc));
                        if (cursorQuery.moveToFirst()) {
                            do {
                                arrayList.add(String.valueOf(cursorQuery.getLong(0)));
                            } while (cursorQuery.moveToNext());
                        }
                    } catch (SQLiteException e) {
                        zzhi.zze("Error in peekHits fetching hitIds: " + e.getMessage());
                        if (cursorQuery != null) {
                        }
                    }
                    cursorQuery.close();
                } catch (Throwable th) {
                    if (cursorQuery != null) {
                        cursorQuery.close();
                    }
                    throw th;
                }
            }
            zzhi.zzd("Store full, deleting " + arrayList.size() + " hits to make room.");
            zzm((String[]) arrayList.toArray(new String[0]));
        }
        zzp(j, str, str2, str3, map, str4);
        if (zzhp.zza().zzd()) {
            zzhi.zzd("Sending hits immediately under preview.");
            zza();
        }
    }

    public final int zzc(String str) {
        SQLiteDatabase sQLiteDatabaseZzn = zzn("Error opening database for getNumRecords.");
        int i = 0;
        if (sQLiteDatabaseZzn == null) {
            return 0;
        }
        Cursor cursorRawQuery = null;
        try {
            try {
                cursorRawQuery = sQLiteDatabaseZzn.rawQuery("SELECT COUNT(*) from gtm_hits", null);
                if (cursorRawQuery.moveToFirst()) {
                    i = (int) cursorRawQuery.getLong(0);
                }
            } catch (SQLiteException e) {
                zzhi.zze("Error getting numStoredRecords: " + e.getMessage());
            }
            return i;
        } finally {
            if (cursorRawQuery != null) {
                cursorRawQuery.close();
            }
        }
    }

    public final void zzm(String[] strArr) {
        int length;
        SQLiteDatabase sQLiteDatabaseZzn;
        if (strArr == null || (length = strArr.length) == 0 || (sQLiteDatabaseZzn = zzn("Error opening database for deleteHits.")) == null) {
            return;
        }
        try {
            sQLiteDatabaseZzn.delete("gtm_hits", android.support.v4.media.session.a.B("HIT_ID in (", TextUtils.join(",", Collections.nCopies(length, "?")), ")"), strArr);
            this.zzl.zza(zzc("gtm_hits") == 0);
        } catch (SQLiteException e) {
            zzhi.zze("Error deleting hits: ".concat(String.valueOf(e.getMessage())));
        }
    }
}
