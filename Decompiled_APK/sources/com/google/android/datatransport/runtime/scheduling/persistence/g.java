package com.google.android.datatransport.runtime.scheduling.persistence;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabaseLockedException;
import android.os.SystemClock;
import android.util.Base64;
import androidx.camera.camera2.internal.T;
import com.google.android.datatransport.runtime.synchronization.SynchronizationException;
import com.j256.ormlite.field.FieldType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class g implements d, com.google.android.datatransport.runtime.synchronization.b, c {
    public static final com.google.android.datatransport.c f = new com.google.android.datatransport.c("proto");
    public final i a;
    public final com.google.android.datatransport.runtime.time.a b;
    public final com.google.android.datatransport.runtime.time.a c;
    public final a d;
    public final javax.inject.a e;

    public g(com.google.android.datatransport.runtime.time.a aVar, com.google.android.datatransport.runtime.time.a aVar2, a aVar3, i iVar, javax.inject.a aVar4) {
        this.a = iVar;
        this.b = aVar;
        this.c = aVar2;
        this.d = aVar3;
        this.e = aVar4;
    }

    public static Long d(SQLiteDatabase sQLiteDatabase, com.google.android.datatransport.runtime.i iVar) {
        StringBuilder sb = new StringBuilder("backend_name = ? and priority = ?");
        ArrayList arrayList = new ArrayList(Arrays.asList(iVar.a, String.valueOf(com.google.android.datatransport.runtime.util.a.a(iVar.c))));
        byte[] bArr = iVar.b;
        if (bArr != null) {
            sb.append(" and extras = ?");
            arrayList.add(Base64.encodeToString(bArr, 0));
        } else {
            sb.append(" and extras is null");
        }
        Cursor cursorQuery = sQLiteDatabase.query("transport_contexts", new String[]{FieldType.FOREIGN_ID_FIELD_SUFFIX}, sb.toString(), (String[]) arrayList.toArray(new String[0]), null, null, null);
        try {
            return !cursorQuery.moveToNext() ? null : Long.valueOf(cursorQuery.getLong(0));
        } finally {
            cursorQuery.close();
        }
    }

    public static String p(Iterable iterable) {
        StringBuilder sb = new StringBuilder("(");
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            sb.append(((b) it2.next()).a);
            if (it2.hasNext()) {
                sb.append(',');
            }
        }
        sb.append(')');
        return sb.toString();
    }

    public static Object q(Cursor cursor, e eVar) {
        try {
            return eVar.apply(cursor);
        } finally {
            cursor.close();
        }
    }

    public final SQLiteDatabase a() {
        i iVar = this.a;
        Objects.requireNonNull(iVar);
        com.google.android.datatransport.runtime.time.a aVar = this.c;
        long jE = aVar.e();
        while (true) {
            try {
                return iVar.getWritableDatabase();
            } catch (SQLiteDatabaseLockedException e) {
                if (aVar.e() >= this.d.c + jE) {
                    throw new SynchronizationException("Timed out while trying to open db.", e);
                }
                SystemClock.sleep(50L);
            }
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.a.close();
    }

    public final Object f(e eVar) {
        SQLiteDatabase sQLiteDatabaseA = a();
        sQLiteDatabaseA.beginTransaction();
        try {
            Object objApply = eVar.apply(sQLiteDatabaseA);
            sQLiteDatabaseA.setTransactionSuccessful();
            return objApply;
        } finally {
            sQLiteDatabaseA.endTransaction();
        }
    }

    public final ArrayList i(SQLiteDatabase sQLiteDatabase, com.google.android.datatransport.runtime.i iVar, int i) {
        ArrayList arrayList = new ArrayList();
        Long lD = d(sQLiteDatabase, iVar);
        if (lD == null) {
            return arrayList;
        }
        q(sQLiteDatabase.query("events", new String[]{FieldType.FOREIGN_ID_FIELD_SUFFIX, "transport_name", "timestamp_ms", "uptime_ms", "payload_encoding", "payload", "code", "inline", "product_id", "pseudonymous_id", "experiment_ids_clear_blob", "experiment_ids_encrypted_blob"}, "context_id = ?", new String[]{lD.toString()}, null, null, null, String.valueOf(i)), new T(this, arrayList, iVar, 10));
        return arrayList;
    }

    public final void j(long j, com.google.android.datatransport.runtime.firebase.transport.c cVar, String str) {
        f(new androidx.camera.core.impl.utils.futures.e(str, cVar, j, 2));
    }

    public final Object l(com.google.android.datatransport.runtime.synchronization.a aVar) {
        SQLiteDatabase sQLiteDatabaseA = a();
        com.google.android.datatransport.runtime.time.a aVar2 = this.c;
        long jE = aVar2.e();
        while (true) {
            try {
                sQLiteDatabaseA.beginTransaction();
                try {
                    Object objA = aVar.a();
                    sQLiteDatabaseA.setTransactionSuccessful();
                    return objA;
                } finally {
                    sQLiteDatabaseA.endTransaction();
                }
            } catch (SQLiteDatabaseLockedException e) {
                if (aVar2.e() >= this.d.c + jE) {
                    throw new SynchronizationException("Timed out while trying to acquire the lock.", e);
                }
                SystemClock.sleep(50L);
            }
        }
    }
}
