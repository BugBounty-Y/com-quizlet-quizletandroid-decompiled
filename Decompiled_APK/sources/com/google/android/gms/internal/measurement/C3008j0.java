package com.google.android.gms.internal.measurement;

import android.content.Context;
import android.os.BadParcelableException;
import android.os.Bundle;
import android.os.NetworkOnMainThreadException;
import android.os.RemoteException;
import android.util.Log;
import android.util.Pair;
import com.google.android.gms.measurement.internal.InterfaceC3887p0;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutorService;

/* renamed from: com.google.android.gms.internal.measurement.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3008j0 {
    public static volatile C3008j0 j;
    public final String a;
    public final com.google.android.gms.common.util.b b;
    public final ExecutorService c;
    public final androidx.appcompat.app.Q d;
    public final ArrayList e;
    public int f;
    public boolean g;
    public final String h;
    public volatile J i;

    /* JADX WARN: Removed duplicated region for block: B:26:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0093  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C3008j0(android.content.Context r14, java.lang.String r15, java.lang.String r16, java.lang.String r17, android.os.Bundle r18) throws java.lang.ClassNotFoundException {
        /*
            r13 = this;
            r2 = r16
            r13.<init>()
            java.lang.Class<com.google.android.gms.internal.measurement.j0> r1 = com.google.android.gms.internal.measurement.C3008j0.class
            java.lang.String r3 = "com.google.firebase.analytics.FirebaseAnalytics"
            r4 = 0
            if (r15 == 0) goto L1b
            if (r17 == 0) goto L1b
            if (r2 == 0) goto L1b
            java.lang.ClassLoader r5 = r1.getClassLoader()     // Catch: java.lang.ClassNotFoundException -> L18
            java.lang.Class.forName(r3, r4, r5)     // Catch: java.lang.ClassNotFoundException -> L18
            goto L1b
        L18:
            r13.a = r15
            goto L1f
        L1b:
            java.lang.String r0 = "FA"
            r13.a = r0
        L1f:
            com.google.android.gms.common.util.b r0 = com.google.android.gms.common.util.b.a
            r13.b = r0
            com.google.android.gms.internal.measurement.c0 r12 = new com.google.android.gms.internal.measurement.c0
            r12.<init>()
            java.util.concurrent.ThreadPoolExecutor r5 = new java.util.concurrent.ThreadPoolExecutor
            java.util.concurrent.TimeUnit r10 = java.util.concurrent.TimeUnit.SECONDS
            java.util.concurrent.LinkedBlockingQueue r11 = new java.util.concurrent.LinkedBlockingQueue
            r11.<init>()
            r7 = 1
            r8 = 60
            r6 = 1
            r5.<init>(r6, r7, r8, r10, r11, r12)
            r0 = 1
            r5.allowCoreThreadTimeOut(r0)
            java.util.concurrent.ExecutorService r5 = java.util.concurrent.Executors.unconfigurableExecutorService(r5)
            r13.c = r5
            androidx.appcompat.app.Q r5 = new androidx.appcompat.app.Q
            r5.<init>(r13)
            r13.d = r5
            java.util.ArrayList r5 = new java.util.ArrayList
            r5.<init>()
            r13.e = r5
            java.lang.String r5 = com.google.android.gms.measurement.internal.AbstractC3883n0.b(r14)     // Catch: java.lang.IllegalStateException -> L6f
            java.lang.String r5 = com.google.android.gms.measurement.internal.AbstractC3883n0.g(r14, r5)     // Catch: java.lang.IllegalStateException -> L6f
            if (r5 == 0) goto L6f
            java.lang.ClassLoader r5 = r1.getClassLoader()     // Catch: java.lang.ClassNotFoundException -> L62
            java.lang.Class.forName(r3, r4, r5)     // Catch: java.lang.ClassNotFoundException -> L62
            goto L6f
        L62:
            r14 = 0
            r13.h = r14
            r13.g = r0
            java.lang.String r14 = r13.a
            java.lang.String r0 = "Disabling data collection. Found google_app_id in strings.xml but Google Analytics for Firebase is missing. Remove this value or add Google Analytics for Firebase to resume data collection."
            android.util.Log.w(r14, r0)
            return
        L6f:
            if (r17 == 0) goto L7e
            if (r2 == 0) goto L7e
            java.lang.ClassLoader r1 = r1.getClassLoader()     // Catch: java.lang.ClassNotFoundException -> L7b
            java.lang.Class.forName(r3, r4, r1)     // Catch: java.lang.ClassNotFoundException -> L7b
            goto L7e
        L7b:
            r13.h = r2
            goto L9a
        L7e:
            java.lang.String r1 = "fa"
            r13.h = r1
            if (r2 == 0) goto L87
            if (r17 == 0) goto L87
            goto L9a
        L87:
            if (r2 != 0) goto L8b
            r1 = r0
            goto L8c
        L8b:
            r1 = r4
        L8c:
            if (r17 != 0) goto L8f
            r4 = r0
        L8f:
            r0 = r1 ^ r4
            if (r0 == 0) goto L9a
            java.lang.String r0 = r13.a
            java.lang.String r1 = "Specified origin or custom app id is null. Both parameters will be ignored."
            android.util.Log.w(r0, r1)
        L9a:
            com.google.android.gms.internal.measurement.X r0 = new com.google.android.gms.internal.measurement.X
            r1 = r13
            r4 = r14
            r3 = r17
            r5 = r18
            r0.<init>(r1, r2, r3, r4, r5)
            r13.c(r0)
            android.content.Context r14 = r14.getApplicationContext()
            android.app.Application r14 = (android.app.Application) r14
            if (r14 != 0) goto Lb8
            java.lang.String r14 = r13.a
            java.lang.String r0 = "Unable to register lifecycle notifications. Application null."
            android.util.Log.w(r14, r0)
            return
        Lb8:
            com.google.android.gms.internal.measurement.i0 r0 = new com.google.android.gms.internal.measurement.i0
            r0.<init>(r13)
            r14.registerActivityLifecycleCallbacks(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3008j0.<init>(android.content.Context, java.lang.String, java.lang.String, java.lang.String, android.os.Bundle):void");
    }

    public static C3008j0 f(Context context, String str, String str2, String str3, Bundle bundle) {
        com.google.android.gms.common.internal.u.h(context);
        if (j == null) {
            synchronized (C3008j0.class) {
                try {
                    if (j == null) {
                        j = new C3008j0(context, str, str2, str3, bundle);
                    }
                } finally {
                }
            }
        }
        return j;
    }

    public final void a(InterfaceC3887p0 interfaceC3887p0) {
        ArrayList arrayList = this.e;
        synchronized (arrayList) {
            for (int i = 0; i < arrayList.size(); i++) {
                try {
                    if (interfaceC3887p0.equals(((Pair) arrayList.get(i)).first)) {
                        Log.w(this.a, "OnEventListener already registered.");
                        return;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            BinderC2993g0 binderC2993g0 = new BinderC2993g0(interfaceC3887p0, 1);
            arrayList.add(new Pair(interfaceC3887p0, binderC2993g0));
            if (this.i != null) {
                try {
                    this.i.registerOnMeasurementEventListener(binderC2993g0);
                    return;
                } catch (BadParcelableException | NetworkOnMainThreadException | RemoteException | IllegalArgumentException | IllegalStateException | NullPointerException | SecurityException | UnsupportedOperationException unused) {
                    Log.w(this.a, "Failed to register event listener on calling thread. Trying again on the dynamite thread.");
                }
            }
            c(new V(this, binderC2993g0, 4));
        }
    }

    public final void b(Exception exc, boolean z, boolean z2) {
        this.g |= z;
        String str = this.a;
        if (z) {
            Log.w(str, "Data collection startup failed. No data will be collected.", exc);
            return;
        }
        if (z2) {
            c(new V(this, exc));
        }
        Log.w(str, "Error with data collection. Data lost.", exc);
    }

    public final void c(AbstractRunnableC2988f0 abstractRunnableC2988f0) {
        this.c.execute(abstractRunnableC2988f0);
    }

    public final int d(String str) {
        G g = new G();
        c(new C2978d0(this, str, g, 1));
        Integer num = (Integer) G.f0(Integer.class, g.X(10000L));
        if (num == null) {
            return 25;
        }
        return num.intValue();
    }

    public final long e() {
        G g = new G();
        c(new C2963a0(this, g, 2));
        Long l = (Long) G.f0(Long.class, g.X(500L));
        if (l != null) {
            return l.longValue();
        }
        long jNanoTime = System.nanoTime();
        this.b.getClass();
        long jNextLong = new Random(jNanoTime ^ System.currentTimeMillis()).nextLong();
        int i = this.f + 1;
        this.f = i;
        return jNextLong + i;
    }

    public final List g(String str, String str2) {
        G g = new G();
        c(new U(this, str, str2, g, 2));
        List list = (List) G.f0(List.class, g.X(5000L));
        return list == null ? Collections.EMPTY_LIST : list;
    }

    public final Map h(String str, String str2, boolean z) {
        G g = new G();
        c(new C2968b0(this, str, str2, z, g));
        Bundle bundleX = g.X(5000L);
        if (bundleX == null || bundleX.size() == 0) {
            return Collections.EMPTY_MAP;
        }
        HashMap map = new HashMap(bundleX.size());
        for (String str3 : bundleX.keySet()) {
            Object obj = bundleX.get(str3);
            if ((obj instanceof Double) || (obj instanceof Long) || (obj instanceof String)) {
                map.put(str3, obj);
            }
        }
        return map;
    }
}
