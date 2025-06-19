package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import android.os.Bundle;
import android.util.Pair;
import androidx.appcompat.app.L;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdRequest$Builder;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.Xv;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class A {
    public final HashMap a = new HashMap();
    public final HashMap b = new HashMap();
    public final Context c;
    public final Kk d;
    public final Xv e;

    public A(Context context, Kk kk, Xv xv) {
        this.c = context;
        this.d = kk;
        this.e = xv;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x002f A[Catch: all -> 0x003f, TryCatch #0 {all -> 0x003f, blocks: (B:3:0x0001, B:5:0x0011, B:10:0x0027, B:12:0x002b, B:15:0x0032, B:17:0x0036, B:21:0x0049, B:25:0x0053, B:28:0x0072, B:29:0x0076, B:31:0x007c, B:20:0x0041, B:14:0x002f), top: B:37:0x0001 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void a(final boolean r10, com.google.android.gms.ads.nonagon.signalgeneration.C r11) {
        /*
            r9 = this;
            monitor-enter(r9)
            java.util.HashMap r0 = r9.a     // Catch: java.lang.Throwable -> L3f
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r10)     // Catch: java.lang.Throwable -> L3f
            java.lang.Object r2 = r0.get(r1)     // Catch: java.lang.Throwable -> L3f
            com.google.android.gms.ads.nonagon.signalgeneration.C r2 = (com.google.android.gms.ads.nonagon.signalgeneration.C) r2     // Catch: java.lang.Throwable -> L3f
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L2f
            com.google.android.gms.ads.internal.j r5 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L3f
            com.google.android.gms.common.util.b r5 = r5.k     // Catch: java.lang.Throwable -> L3f
            r5.getClass()     // Catch: java.lang.Throwable -> L3f
            long r5 = java.lang.System.currentTimeMillis()     // Catch: java.lang.Throwable -> L3f
            long r7 = r2.c     // Catch: java.lang.Throwable -> L3f
            int r5 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r5 > 0) goto L24
            r5 = r4
            goto L25
        L24:
            r5 = r3
        L25:
            if (r5 != 0) goto L2f
            androidx.appcompat.app.L r2 = r2.a     // Catch: java.lang.Throwable -> L3f
            if (r2 == 0) goto L2f
            androidx.appcompat.app.L r2 = r11.a     // Catch: java.lang.Throwable -> L3f
            if (r2 == 0) goto L32
        L2f:
            r0.put(r1, r11)     // Catch: java.lang.Throwable -> L3f
        L32:
            androidx.appcompat.app.L r0 = r11.a     // Catch: java.lang.Throwable -> L3f
            if (r0 == 0) goto L41
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.AbstractC1911c8.f     // Catch: java.lang.Throwable -> L3f
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L3f
            java.lang.Long r0 = (java.lang.Long) r0     // Catch: java.lang.Throwable -> L3f
            goto L49
        L3f:
            r10 = move-exception
            goto L88
        L41:
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.AbstractC1911c8.g     // Catch: java.lang.Throwable -> L3f
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L3f
            java.lang.Long r0 = (java.lang.Long) r0     // Catch: java.lang.Throwable -> L3f
        L49:
            long r5 = r0.longValue()     // Catch: java.lang.Throwable -> L3f
            androidx.appcompat.app.L r0 = r11.a     // Catch: java.lang.Throwable -> L3f
            if (r0 != 0) goto L52
            goto L53
        L52:
            r4 = r3
        L53:
            com.google.android.gms.internal.ads.id r0 = com.google.android.gms.internal.ads.AbstractC2270kd.d     // Catch: java.lang.Throwable -> L3f
            com.google.android.gms.ads.nonagon.signalgeneration.z r2 = new com.google.android.gms.ads.nonagon.signalgeneration.z     // Catch: java.lang.Throwable -> L3f
            r2.<init>()     // Catch: java.lang.Throwable -> L3f
            java.util.concurrent.TimeUnit r10 = java.util.concurrent.TimeUnit.SECONDS     // Catch: java.lang.Throwable -> L3f
            r0.schedule(r2, r5, r10)     // Catch: java.lang.Throwable -> L3f
            java.util.HashMap r10 = r9.b     // Catch: java.lang.Throwable -> L3f
            java.lang.Object r0 = r10.get(r1)     // Catch: java.lang.Throwable -> L3f
            java.util.List r0 = (java.util.List) r0     // Catch: java.lang.Throwable -> L3f
            java.util.ArrayList r2 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L3f
            r2.<init>()     // Catch: java.lang.Throwable -> L3f
            r10.put(r1, r2)     // Catch: java.lang.Throwable -> L3f
            if (r0 != 0) goto L72
            goto L86
        L72:
            java.util.Iterator r10 = r0.iterator()     // Catch: java.lang.Throwable -> L3f
        L76:
            boolean r0 = r10.hasNext()     // Catch: java.lang.Throwable -> L3f
            if (r0 == 0) goto L86
            java.lang.Object r0 = r10.next()     // Catch: java.lang.Throwable -> L3f
            android.util.Pair r0 = (android.util.Pair) r0     // Catch: java.lang.Throwable -> L3f
            r9.d(r11, r0, r3)     // Catch: java.lang.Throwable -> L3f
            goto L76
        L86:
            monitor-exit(r9)
            return
        L88:
            monitor-exit(r9)     // Catch: java.lang.Throwable -> L3f
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.nonagon.signalgeneration.A.a(boolean, com.google.android.gms.ads.nonagon.signalgeneration.C):void");
    }

    public final synchronized void b(Object obj, com.google.android.gms.ads.query.a aVar) {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        AbstractC2270kd.f.execute(new androidx.core.provider.k(this, obj, new Pair(aVar, Long.valueOf(System.currentTimeMillis())), 7));
    }

    public final void c(boolean z) {
        HashMap map = this.b;
        Boolean boolValueOf = Boolean.valueOf(z);
        if (map.containsKey(boolValueOf)) {
            return;
        }
        map.put(boolValueOf, new ArrayList());
        ((C2227jd) this.e).submit(new com.bumptech.glide.manager.o(z, 3, this));
    }

    public final void d(C c, Pair pair, boolean z) {
        c.e.set(true);
        L l = c.a;
        if (l != null) {
            ((com.google.android.gms.ads.query.a) pair.first).b(l);
        } else {
            ((com.google.android.gms.ads.query.a) pair.first).a(c.b);
        }
        Pair pair2 = new Pair("se", "query_g");
        Pair pair3 = new Pair("ad_format", "BANNER");
        Pair pair4 = new Pair("rtype", Integer.toString(6));
        Pair pair5 = new Pair("scar", "true");
        com.google.android.gms.ads.internal.j.C.k.getClass();
        AbstractC3429b3.f(this.d, "sgpcr", pair2, pair3, pair4, pair5, new Pair("lat_ms", Long.toString(System.currentTimeMillis() - ((Long) pair.second).longValue())), new Pair("sgpc_h", Boolean.toString(z)), new Pair("sgpc_rs", Boolean.toString(l != null)));
    }

    public final synchronized void e(boolean z, boolean z2) {
        Throwable th;
        try {
            try {
                Bundle bundle = new Bundle();
                bundle.putString("query_info_type", "requester_type_6");
                bundle.putBoolean("accept_3p_cookie", z);
                HashMap map = this.a;
                Boolean boolValueOf = Boolean.valueOf(z);
                C c = (C) map.get(boolValueOf);
                int i = 0;
                if (z2 && c != null) {
                    try {
                        i = c.d + 1;
                    } catch (Throwable th2) {
                        th = th2;
                        throw th;
                    }
                }
                C c2 = (C) map.get(boolValueOf);
                B b = new B(this, z, i, c2 == null ? null : Boolean.valueOf(c2.e.get()), this.d);
                AdRequest$Builder adRequest$Builder = (AdRequest$Builder) new AdRequest$Builder().addNetworkExtrasBundle(AdMobAdapter.class, bundle);
                adRequest$Builder.getClass();
                com.google.android.gms.ads.g gVar = new com.google.android.gms.ads.g(adRequest$Builder);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.cb)).booleanValue()) {
                    ((C2227jd) this.e).submit(new com.android.billingclient.api.n(this, gVar, b, 6));
                } else {
                    L.J(this.c, gVar, b);
                }
            } catch (Throwable th3) {
                th = th3;
                th = th;
                throw th;
            }
        } catch (Throwable th4) {
            th = th4;
            th = th;
            throw th;
        }
    }
}
