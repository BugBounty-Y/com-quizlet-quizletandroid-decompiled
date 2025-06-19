package com.google.android.gms.internal.measurement;

import android.net.Uri;
import android.util.Log;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class F1 {
    public static final Object g = new Object();
    public static volatile C3063u1 h;
    public static final AtomicInteger i;
    public final androidx.appcompat.app.K a;
    public final String b;
    public final Object c;
    public volatile int d = -1;
    public volatile Object e;
    public final /* synthetic */ int f;

    static {
        new AtomicReference();
        i = new AtomicInteger();
    }

    public /* synthetic */ F1(androidx.appcompat.app.K k, String str, Object obj, int i2) {
        this.f = i2;
        if (((Uri) k.b) == null) {
            throw new IllegalArgumentException("Must pass a valid SharedPreferences file name or ContentProvider URI");
        }
        this.a = k;
        this.b = str;
        this.c = obj;
    }

    public final Object a(Object obj) {
        switch (this.f) {
            case 0:
                if (!(obj instanceof Long)) {
                    if (obj instanceof String) {
                        try {
                            break;
                        } catch (NumberFormatException unused) {
                        }
                    }
                    Log.e("PhenotypeFlag", "Invalid long value for " + this.b + ": " + obj.toString());
                    break;
                } else {
                    break;
                }
            case 1:
                if (!(obj instanceof Boolean)) {
                    if (obj instanceof String) {
                        String str = (String) obj;
                        if (!AbstractC3048r1.b.matcher(str).matches()) {
                            if (AbstractC3048r1.c.matcher(str).matches()) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    Log.e("PhenotypeFlag", "Invalid boolean value for " + this.b + ": " + obj.toString());
                    break;
                } else {
                    break;
                }
            case 2:
                if (!(obj instanceof Double)) {
                    if (!(obj instanceof Float)) {
                        if (obj instanceof String) {
                            try {
                                break;
                            } catch (NumberFormatException unused2) {
                            }
                        }
                        Log.e("PhenotypeFlag", "Invalid double value for " + this.b + ": " + obj.toString());
                        break;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            default:
                if (obj instanceof String) {
                    break;
                }
                break;
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0058 A[PHI: r2
  0x0058: PHI (r2v1 com.google.common.base.i) = (r2v0 com.google.common.base.i), (r2v5 com.google.common.base.i), (r2v5 com.google.common.base.i) binds: [B:8:0x0014, B:10:0x0022, B:16:0x0047] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x006b A[Catch: all -> 0x0055, TryCatch #0 {all -> 0x0055, blocks: (B:5:0x000b, B:7:0x000f, B:9:0x0016, B:11:0x0024, B:13:0x0034, B:17:0x0048, B:24:0x005e, B:26:0x006b, B:28:0x0073, B:31:0x0086, B:33:0x0094, B:45:0x00b9, B:48:0x00c1, B:49:0x00c4, B:50:0x00c8, B:37:0x009d, B:39:0x00a1, B:41:0x00af, B:43:0x00b5, B:51:0x00cd, B:52:0x00cf, B:14:0x0041, B:53:0x00d0), top: B:59:0x000b }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0099  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x00cd A[Catch: all -> 0x0055, TryCatch #0 {all -> 0x0055, blocks: (B:5:0x000b, B:7:0x000f, B:9:0x0016, B:11:0x0024, B:13:0x0034, B:17:0x0048, B:24:0x005e, B:26:0x006b, B:28:0x0073, B:31:0x0086, B:33:0x0094, B:45:0x00b9, B:48:0x00c1, B:49:0x00c4, B:50:0x00c8, B:37:0x009d, B:39:0x00a1, B:41:0x00af, B:43:0x00b5, B:51:0x00cd, B:52:0x00cf, B:14:0x0041, B:53:0x00d0), top: B:59:0x000b }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b() {
        /*
            r9 = this;
            java.util.concurrent.atomic.AtomicInteger r0 = com.google.android.gms.internal.measurement.F1.i
            int r0 = r0.get()
            int r1 = r9.d
            if (r1 >= r0) goto Ld4
            monitor-enter(r9)
            int r1 = r9.d     // Catch: java.lang.Throwable -> L55
            if (r1 >= r0) goto Ld0
            com.google.android.gms.internal.measurement.u1 r1 = com.google.android.gms.internal.measurement.F1.h     // Catch: java.lang.Throwable -> L55
            com.google.common.base.a r2 = com.google.common.base.a.a     // Catch: java.lang.Throwable -> L55
            r3 = 0
            if (r1 == 0) goto L58
            com.google.common.base.l r2 = r1.b     // Catch: java.lang.Throwable -> L55
            java.lang.Object r2 = r2.get()     // Catch: java.lang.Throwable -> L55
            com.google.common.base.i r2 = (com.google.common.base.i) r2     // Catch: java.lang.Throwable -> L55
            boolean r4 = r2.b()     // Catch: java.lang.Throwable -> L55
            if (r4 == 0) goto L58
            java.lang.Object r4 = r2.a()     // Catch: java.lang.Throwable -> L55
            com.google.android.gms.internal.measurement.w1 r4 = (com.google.android.gms.internal.measurement.C3073w1) r4     // Catch: java.lang.Throwable -> L55
            androidx.appcompat.app.K r5 = r9.a     // Catch: java.lang.Throwable -> L55
            java.lang.Object r5 = r5.b     // Catch: java.lang.Throwable -> L55
            android.net.Uri r5 = (android.net.Uri) r5     // Catch: java.lang.Throwable -> L55
            java.lang.String r6 = r9.b     // Catch: java.lang.Throwable -> L55
            if (r5 == 0) goto L41
            androidx.collection.V r4 = r4.a     // Catch: java.lang.Throwable -> L55
            java.lang.String r5 = r5.toString()     // Catch: java.lang.Throwable -> L55
            java.lang.Object r4 = r4.get(r5)     // Catch: java.lang.Throwable -> L55
            androidx.collection.V r4 = (androidx.collection.V) r4     // Catch: java.lang.Throwable -> L55
            goto L45
        L41:
            r4.getClass()     // Catch: java.lang.Throwable -> L55
            r4 = r3
        L45:
            if (r4 != 0) goto L48
            goto L58
        L48:
            java.lang.String r5 = ""
            java.lang.String r5 = r5.concat(r6)     // Catch: java.lang.Throwable -> L55
            java.lang.Object r4 = r4.get(r5)     // Catch: java.lang.Throwable -> L55
            java.lang.String r4 = (java.lang.String) r4     // Catch: java.lang.Throwable -> L55
            goto L59
        L55:
            r0 = move-exception
            goto Ld2
        L58:
            r4 = r3
        L59:
            if (r1 == 0) goto L5d
            r5 = 1
            goto L5e
        L5d:
            r5 = 0
        L5e:
            java.lang.String r6 = "Must call PhenotypeFlagInitializer.maybeInit() first"
            com.google.common.base.b.h(r6, r5)     // Catch: java.lang.Throwable -> L55
            androidx.appcompat.app.K r5 = r9.a     // Catch: java.lang.Throwable -> L55
            java.lang.Object r6 = r5.b     // Catch: java.lang.Throwable -> L55
            android.net.Uri r6 = (android.net.Uri) r6     // Catch: java.lang.Throwable -> L55
            if (r6 == 0) goto Lcd
            android.content.Context r7 = r1.a     // Catch: java.lang.Throwable -> L55
            boolean r7 = com.google.android.gms.internal.measurement.A1.a(r7, r6)     // Catch: java.lang.Throwable -> L55
            if (r7 == 0) goto L83
            android.content.Context r7 = r1.a     // Catch: java.lang.Throwable -> L55
            android.content.ContentResolver r7 = r7.getContentResolver()     // Catch: java.lang.Throwable -> L55
            com.google.android.gms.internal.measurement.C1 r8 = new com.google.android.gms.internal.measurement.C1     // Catch: java.lang.Throwable -> L55
            r8.<init>()     // Catch: java.lang.Throwable -> L55
            com.google.android.gms.internal.measurement.v1 r6 = com.google.android.gms.internal.measurement.C3068v1.a(r7, r6, r8)     // Catch: java.lang.Throwable -> L55
            goto L84
        L83:
            r6 = r3
        L84:
            if (r6 == 0) goto L99
            java.lang.String r7 = r9.b     // Catch: java.lang.Throwable -> L55
            java.util.Map r6 = r6.b()     // Catch: java.lang.Throwable -> L55
            java.lang.Object r6 = r6.get(r7)     // Catch: java.lang.Throwable -> L55
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Throwable -> L55
            if (r6 == 0) goto L99
            java.lang.Object r6 = r9.a(r6)     // Catch: java.lang.Throwable -> L55
            goto L9a
        L99:
            r6 = r3
        L9a:
            if (r6 == 0) goto L9d
            goto Lb9
        L9d:
            boolean r5 = r5.a     // Catch: java.lang.Throwable -> L55
            if (r5 != 0) goto Lb3
            android.content.Context r1 = r1.a     // Catch: java.lang.Throwable -> L55
            com.google.android.gms.internal.measurement.y1 r1 = com.google.android.gms.internal.measurement.C3083y1.i(r1)     // Catch: java.lang.Throwable -> L55
            java.lang.String r5 = r9.b     // Catch: java.lang.Throwable -> L55
            java.lang.String r1 = r1.m(r5)     // Catch: java.lang.Throwable -> L55
            if (r1 == 0) goto Lb3
            java.lang.Object r3 = r9.a(r1)     // Catch: java.lang.Throwable -> L55
        Lb3:
            if (r3 != 0) goto Lb8
            java.lang.Object r6 = r9.c     // Catch: java.lang.Throwable -> L55
            goto Lb9
        Lb8:
            r6 = r3
        Lb9:
            boolean r1 = r2.b()     // Catch: java.lang.Throwable -> L55
            if (r1 == 0) goto Lc8
            if (r4 != 0) goto Lc4
            java.lang.Object r6 = r9.c     // Catch: java.lang.Throwable -> L55
            goto Lc8
        Lc4:
            java.lang.Object r6 = r9.a(r4)     // Catch: java.lang.Throwable -> L55
        Lc8:
            r9.e = r6     // Catch: java.lang.Throwable -> L55
            r9.d = r0     // Catch: java.lang.Throwable -> L55
            goto Ld0
        Lcd:
            android.content.Context r0 = r1.a     // Catch: java.lang.Throwable -> L55
            throw r3     // Catch: java.lang.Throwable -> L55
        Ld0:
            monitor-exit(r9)     // Catch: java.lang.Throwable -> L55
            goto Ld4
        Ld2:
            monitor-exit(r9)     // Catch: java.lang.Throwable -> L55
            throw r0
        Ld4:
            java.lang.Object r0 = r9.e
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.F1.b():java.lang.Object");
    }
}
