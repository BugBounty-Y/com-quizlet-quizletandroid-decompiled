package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.database.Cursor;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.os.Build;
import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
final class zzhl extends zzfp {
    final /* synthetic */ zzhm zza;
    private boolean zzb;
    private long zzc;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public zzhl(zzhm zzhmVar, Context context, String str) {
        super(context, "gtm_urls.db", null, 1);
        this.zza = zzhmVar;
        this.zzc = 0L;
    }

    private static final boolean zza(String str, SQLiteDatabase sQLiteDatabase) {
        boolean zMoveToFirst;
        Cursor cursorQuery = null;
        try {
            cursorQuery = sQLiteDatabase.query("SQLITE_MASTER", new String[]{"name"}, "name=?", new String[]{str}, null, null, null);
            zMoveToFirst = cursorQuery.moveToFirst();
        } catch (SQLiteException unused) {
            zMoveToFirst = false;
        } catch (Throwable th) {
            if (cursorQuery == null) {
                throw th;
            }
            cursorQuery.close();
            throw th;
        }
        if (cursorQuery != null) {
            cursorQuery.close();
        }
        return zMoveToFirst;
    }

    private static final void zzb(SQLiteDatabase sQLiteDatabase, String str, List list) {
        Cursor cursorRawQuery = sQLiteDatabase.rawQuery("SELECT * FROM " + str + " WHERE 0", null);
        HashSet hashSet = new HashSet();
        try {
            for (String str2 : cursorRawQuery.getColumnNames()) {
                hashSet.add(str2);
            }
            cursorRawQuery.close();
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                String str3 = (String) it2.next();
                if (!hashSet.remove(str3)) {
                    throw new SQLiteException(AbstractC0147y.e("Database column ", str3, " missing in table ", str, "."));
                }
            }
            if (!hashSet.isEmpty()) {
                throw new SQLiteException(a.B("Database has extra columns in table ", str, "."));
            }
        } catch (Throwable th) {
            cursorRawQuery.close();
            throw th;
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final SQLiteDatabase getWritableDatabase() {
        SQLiteDatabase writableDatabase;
        if (this.zzb && this.zzc + 3600000 > this.zza.zzj.currentTimeMillis()) {
            throw new SQLiteException("Database creation failed");
        }
        this.zzb = true;
        this.zzc = this.zza.zzj.currentTimeMillis();
        try {
            writableDatabase = super.getWritableDatabase();
        } catch (SQLiteException unused) {
            zzhm zzhmVar = this.zza;
            zzhmVar.zzg.getDatabasePath(zzhmVar.zzh).delete();
            writableDatabase = null;
        }
        if (writableDatabase == null) {
            writableDatabase = super.getWritableDatabase();
        }
        this.zzb = false;
        return writableDatabase;
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase) {
        String path = sQLiteDatabase.getPath();
        try {
            if (Integer.parseInt(Build.VERSION.SDK) < 9) {
                return;
            }
            File file = new File(path);
            file.setReadable(false, false);
            file.setWritable(false, false);
            file.setReadable(true, true);
            file.setWritable(true, true);
        } catch (NumberFormatException unused) {
            zzhi.zza("Invalid version number: ".concat(String.valueOf(Build.VERSION.SDK)));
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onDowngrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onOpen(SQLiteDatabase sQLiteDatabase) throws SQLException {
        if (zza("gtm_hit_unique_ids", sQLiteDatabase)) {
            zzb(sQLiteDatabase, "gtm_hit_unique_ids", Arrays.asList("hit_unique_id"));
        } else {
            sQLiteDatabase.execSQL(zzhm.zza);
        }
        if (zza("gtm_hits", sQLiteDatabase)) {
            zzb(sQLiteDatabase, "gtm_hits", Arrays.asList("hit_id", "hit_url", "hit_time", "hit_first_send_time", "hit_method", "hit_unique_id", "hit_headers", "hit_body"));
        } else {
            sQLiteDatabase.execSQL(zzhm.zzb);
        }
        sQLiteDatabase.execSQL(zzhm.zzc);
        sQLiteDatabase.execSQL(zzhm.zzd);
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public final void onUpgrade(SQLiteDatabase sQLiteDatabase, int i, int i2) {
    }
}
