package com.google.android.gms.measurement.internal;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;

/* loaded from: classes2.dex */
public final class C extends AbstractC3888q {
    public static final String[] f = {"app_version", "ALTER TABLE messages ADD COLUMN app_version TEXT;", "app_version_int", "ALTER TABLE messages ADD COLUMN app_version_int INTEGER;"};
    public final C3872i d;
    public boolean e;

    public C(Y y) {
        super(y);
        this.d = new C3872i(this, ((Y) this.b).a);
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return false;
    }

    public final SQLiteDatabase V() {
        if (this.e) {
            return null;
        }
        SQLiteDatabase writableDatabase = this.d.getWritableDatabase();
        if (writableDatabase != null) {
            return writableDatabase;
        }
        this.e = true;
        return null;
    }

    public final void W() {
        int iDelete;
        Y y = (Y) this.b;
        S();
        try {
            SQLiteDatabase sQLiteDatabaseV = V();
            if (sQLiteDatabaseV == null || (iDelete = sQLiteDatabaseV.delete("messages", null, null)) <= 0) {
                return;
            }
            I i = y.i;
            Y.k(i);
            i.o.g("Reset local analytics data. records", Integer.valueOf(iDelete));
        } catch (SQLiteException e) {
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Error resetting local analytics data. error", e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0073 A[PHI: r4
  0x0073: PHI (r4v3 int) = (r4v1 int), (r4v1 int), (r4v4 int) binds: [B:28:0x006a, B:34:0x0083, B:31:0x0071] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void X() {
        /*
            r10 = this;
            java.lang.String r0 = "Error deleting app launch break from local database"
            r10.S()
            boolean r1 = r10.e
            if (r1 == 0) goto Lb
            goto L9b
        Lb:
            java.lang.Object r1 = r10.b
            com.google.android.gms.measurement.internal.Y r1 = (com.google.android.gms.measurement.internal.Y) r1
            android.content.Context r2 = r1.a
            java.lang.String r3 = "google_app_measurement_local.db"
            java.io.File r2 = r2.getDatabasePath(r3)
            boolean r2 = r2.exists()
            if (r2 == 0) goto L9b
            r2 = 0
            r3 = 5
            r4 = r3
        L20:
            if (r2 >= r3) goto L8f
            r5 = 1
            r6 = 0
            android.database.sqlite.SQLiteDatabase r6 = r10.V()     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            if (r6 != 0) goto L34
            r10.e = r5     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            goto L9b
        L2e:
            r0 = move-exception
            goto L89
        L30:
            r7 = move-exception
            goto L51
        L32:
            r7 = move-exception
            goto L77
        L34:
            r6.beginTransaction()     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            java.lang.String r7 = "messages"
            java.lang.String r8 = "type == ?"
            r9 = 3
            java.lang.String r9 = java.lang.Integer.toString(r9)     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            java.lang.String[] r9 = new java.lang.String[]{r9}     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            r6.delete(r7, r8, r9)     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            r6.setTransactionSuccessful()     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            r6.endTransaction()     // Catch: java.lang.Throwable -> L2e android.database.sqlite.SQLiteException -> L30 android.database.sqlite.SQLiteFullException -> L32 android.database.sqlite.SQLiteDatabaseLockedException -> L6b
            r6.close()
            return
        L51:
            if (r6 == 0) goto L5c
            boolean r8 = r6.inTransaction()     // Catch: java.lang.Throwable -> L2e
            if (r8 == 0) goto L5c
            r6.endTransaction()     // Catch: java.lang.Throwable -> L2e
        L5c:
            com.google.android.gms.measurement.internal.I r8 = r1.i     // Catch: java.lang.Throwable -> L2e
            com.google.android.gms.measurement.internal.Y.k(r8)     // Catch: java.lang.Throwable -> L2e
            com.google.android.gms.internal.ads.Ka r8 = r8.g     // Catch: java.lang.Throwable -> L2e
            r8.g(r0, r7)     // Catch: java.lang.Throwable -> L2e
            r10.e = r5     // Catch: java.lang.Throwable -> L2e
            if (r6 == 0) goto L86
            goto L73
        L6b:
            long r7 = (long) r4     // Catch: java.lang.Throwable -> L2e
            android.os.SystemClock.sleep(r7)     // Catch: java.lang.Throwable -> L2e
            int r4 = r4 + 20
            if (r6 == 0) goto L86
        L73:
            r6.close()
            goto L86
        L77:
            com.google.android.gms.measurement.internal.I r8 = r1.i     // Catch: java.lang.Throwable -> L2e
            com.google.android.gms.measurement.internal.Y.k(r8)     // Catch: java.lang.Throwable -> L2e
            com.google.android.gms.internal.ads.Ka r8 = r8.g     // Catch: java.lang.Throwable -> L2e
            r8.g(r0, r7)     // Catch: java.lang.Throwable -> L2e
            r10.e = r5     // Catch: java.lang.Throwable -> L2e
            if (r6 == 0) goto L86
            goto L73
        L86:
            int r2 = r2 + 1
            goto L20
        L89:
            if (r6 == 0) goto L8e
            r6.close()
        L8e:
            throw r0
        L8f:
            com.google.android.gms.measurement.internal.I r0 = r1.i
            com.google.android.gms.measurement.internal.Y.k(r0)
            java.lang.String r1 = "Error deleting app launch break from local database in reasonable time"
            com.google.android.gms.internal.ads.Ka r0 = r0.j
            r0.f(r1)
        L9b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C.X():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:120:0x0173 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:121:0x0173 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0173 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a4 A[Catch: all -> 0x0094, SQLiteDatabaseLockedException -> 0x0097, SQLiteException -> 0x00f2, SQLiteFullException -> 0x00f6, TRY_ENTER, TRY_LEAVE, TryCatch #8 {all -> 0x0094, blocks: (B:31:0x0089, B:33:0x008f, B:40:0x00a4, B:42:0x00ab, B:44:0x00c8, B:46:0x00d3, B:61:0x00fd, B:75:0x0125, B:77:0x012b, B:78:0x012e, B:93:0x015e, B:85:0x0149), top: B:109:0x0089 }] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0125 A[Catch: all -> 0x0094, TRY_ENTER, TryCatch #8 {all -> 0x0094, blocks: (B:31:0x0089, B:33:0x008f, B:40:0x00a4, B:42:0x00ab, B:44:0x00c8, B:46:0x00d3, B:61:0x00fd, B:75:0x0125, B:77:0x012b, B:78:0x012e, B:93:0x015e, B:85:0x0149), top: B:109:0x0089 }] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x013e  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0155 A[PHI: r8 r11 r16
  0x0155: PHI (r8v5 int) = (r8v3 int), (r8v3 int), (r8v6 int) binds: [B:81:0x0141, B:96:0x0170, B:89:0x0153] A[DONT_GENERATE, DONT_INLINE]
  0x0155: PHI (r11v7 android.database.sqlite.SQLiteDatabase) = 
  (r11v5 android.database.sqlite.SQLiteDatabase)
  (r11v6 android.database.sqlite.SQLiteDatabase)
  (r11v8 android.database.sqlite.SQLiteDatabase)
 binds: [B:81:0x0141, B:96:0x0170, B:89:0x0153] A[DONT_GENERATE, DONT_INLINE]
  0x0155: PHI (r16v7 boolean) = (r16v4 boolean), (r16v5 boolean), (r16v8 boolean) binds: [B:81:0x0141, B:96:0x0170, B:89:0x0153] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x016d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean Y(int r20, byte[] r21) {
        /*
            Method dump skipped, instructions count: 402
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C.Y(int, byte[]):boolean");
    }
}
