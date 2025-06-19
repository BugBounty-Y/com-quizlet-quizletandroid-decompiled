package com.google.android.gms.internal.measurement;

import android.content.ContentResolver;
import android.net.Uri;
import androidx.collection.C0207e;
import androidx.collection.C0208f;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.measurement.v1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3068v1 {
    public static final C0208f h = new C0208f(0);
    public static final String[] i = {"key", "value"};
    public final ContentResolver a;
    public final Uri b;
    public final Runnable c;
    public final androidx.compose.ui.platform.o1 d;
    public volatile Map f;
    public final Object e = new Object();
    public final ArrayList g = new ArrayList();

    public C3068v1(ContentResolver contentResolver, Uri uri, Runnable runnable) {
        contentResolver.getClass();
        uri.getClass();
        this.a = contentResolver;
        this.b = uri;
        this.c = runnable;
        this.d = new androidx.compose.ui.platform.o1(this, 3);
    }

    public static C3068v1 a(ContentResolver contentResolver, Uri uri, Runnable runnable) {
        C3068v1 c3068v1;
        synchronized (C3068v1.class) {
            C0208f c0208f = h;
            c3068v1 = (C3068v1) c0208f.get(uri);
            if (c3068v1 == null) {
                try {
                    C3068v1 c3068v12 = new C3068v1(contentResolver, uri, runnable);
                    try {
                        contentResolver.registerContentObserver(uri, false, c3068v12.d);
                        c0208f.put(uri, c3068v12);
                    } catch (SecurityException unused) {
                    }
                    c3068v1 = c3068v12;
                } catch (SecurityException unused2) {
                }
            }
        }
        return c3068v1;
    }

    public static synchronized void c() {
        try {
            C0208f c0208f = h;
            Iterator it2 = ((C0207e) c0208f.values()).iterator();
            while (it2.hasNext()) {
                C3068v1 c3068v1 = (C3068v1) it2.next();
                c3068v1.a.unregisterContentObserver(c3068v1.d);
            }
            c0208f.clear();
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x0051 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0052  */
    /* JADX WARN: Type inference failed for: r0v4, types: [android.os.StrictMode$ThreadPolicy, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.Map b() {
        /*
            r5 = this;
            java.util.Map r0 = r5.f
            if (r0 != 0) goto L4f
            java.lang.Object r1 = r5.e
            monitor-enter(r1)
            java.util.Map r0 = r5.f     // Catch: java.lang.Throwable -> L2a
            if (r0 != 0) goto L4b
            android.os.StrictMode$ThreadPolicy r0 = android.os.StrictMode.allowThreadDiskReads()     // Catch: java.lang.Throwable -> L2a
            com.google.android.gms.internal.measurement.i2 r2 = new com.google.android.gms.internal.measurement.i2     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
            r2.<init>(r5)     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
            java.lang.Object r2 = r2.a()     // Catch: java.lang.SecurityException -> L19 java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30
            goto L24
        L19:
            long r3 = android.os.Binder.clearCallingIdentity()     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
            java.lang.Object r2 = r2.a()     // Catch: java.lang.Throwable -> L34
            android.os.Binder.restoreCallingIdentity(r3)     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
        L24:
            java.util.Map r2 = (java.util.Map) r2     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
        L26:
            android.os.StrictMode.setThreadPolicy(r0)     // Catch: java.lang.Throwable -> L2a
            goto L43
        L2a:
            r0 = move-exception
            goto L4d
        L2c:
            r2 = move-exception
            goto L47
        L2e:
            r2 = move-exception
            goto L39
        L30:
            r2 = move-exception
            goto L39
        L32:
            r2 = move-exception
            goto L39
        L34:
            r2 = move-exception
            android.os.Binder.restoreCallingIdentity(r3)     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
            throw r2     // Catch: java.lang.Throwable -> L2c java.lang.IllegalStateException -> L2e android.database.sqlite.SQLiteException -> L30 java.lang.SecurityException -> L32
        L39:
            java.lang.String r3 = "ConfigurationContentLdr"
            java.lang.String r4 = "Unable to query ContentProvider, using default values"
            android.util.Log.w(r3, r4, r2)     // Catch: java.lang.Throwable -> L2c
            java.util.Map r2 = java.util.Collections.EMPTY_MAP     // Catch: java.lang.Throwable -> L2c
            goto L26
        L43:
            r5.f = r2     // Catch: java.lang.Throwable -> L2a
            r0 = r2
            goto L4b
        L47:
            android.os.StrictMode.setThreadPolicy(r0)     // Catch: java.lang.Throwable -> L2a
            throw r2     // Catch: java.lang.Throwable -> L2a
        L4b:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L2a
            goto L4f
        L4d:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L2a
            throw r0
        L4f:
            if (r0 == 0) goto L52
            return r0
        L52:
            java.util.Map r0 = java.util.Collections.EMPTY_MAP
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3068v1.b():java.util.Map");
    }
}
