package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.ConnectivityManager;
import com.google.android.gms.ads.internal.client.zzfp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.internal.ads.zr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2928zr {
    public final ConcurrentHashMap a = new ConcurrentHashMap();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final Er c;
    public final Fi d;
    public final Context e;
    public volatile ConnectivityManager f;
    public final com.google.android.gms.common.util.a g;
    public AtomicInteger h;

    public C2928zr(Er er, Fi fi, Context context, com.google.android.gms.common.util.a aVar) {
        this.c = er;
        this.d = fi;
        this.e = context;
        this.g = aVar;
    }

    public static String a(String str, com.google.android.gms.ads.c cVar) {
        return android.support.v4.media.session.a.l(str, "#", cVar == null ? "NULL" : cVar.name());
    }

    public static void b(C2928zr c2928zr, boolean z) {
        synchronized (c2928zr) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.v)).booleanValue()) {
                c2928zr.f(z);
            }
        }
    }

    public final synchronized C2670tr c(String str, com.google.android.gms.ads.c cVar) {
        return (C2670tr) this.a.get(a(str, cVar));
    }

    public final synchronized Object d(Class cls, String str, com.google.android.gms.ads.c cVar) {
        Ar ar = new Ar(new Fp(str, false, cVar, 3));
        Fi fi = this.d;
        com.google.android.gms.common.util.a aVar = this.g;
        fi.z("poll_ad", "ppac_ts", aVar.currentTimeMillis(), -1, -1, null, ar);
        C2670tr c2670trC = c(str, cVar);
        if (c2670trC == null) {
            return null;
        }
        try {
            String strH = c2670trC.h();
            Object objG = c2670trC.g();
            Object objCast = objG == null ? null : cls.cast(objG);
            if (objCast != null) {
                fi.s(aVar.currentTimeMillis(), c2670trC.e.d, c2670trC.f(), strH, ar);
            }
            return objCast;
        } catch (ClassCastException e) {
            com.google.android.gms.ads.internal.j.C.h.h("PreloadAdManager.pollAd", e);
            "Unable to cast ad to the requested type:".concat(cls.getName());
            com.google.android.gms.ads.internal.util.A.m();
            return null;
        }
    }

    public final synchronized ArrayList e(ArrayList arrayList) {
        ArrayList arrayList2;
        try {
            HashSet hashSet = new HashSet();
            arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                zzfp zzfpVar = (zzfp) it2.next();
                String strA = a(zzfpVar.a, com.google.android.gms.ads.c.a(zzfpVar.b));
                hashSet.add(strA);
                ConcurrentHashMap concurrentHashMap = this.a;
                C2670tr c2670tr = (C2670tr) concurrentHashMap.get(strA);
                if (c2670tr == null) {
                    ConcurrentHashMap concurrentHashMap2 = this.b;
                    if (concurrentHashMap2.containsKey(strA)) {
                        C2670tr c2670tr2 = (C2670tr) concurrentHashMap2.get(strA);
                        if (c2670tr2.e.equals(zzfpVar)) {
                            c2670tr2.l(zzfpVar.d);
                            c2670tr2.k();
                            concurrentHashMap.put(strA, c2670tr2);
                            concurrentHashMap2.remove(strA);
                        }
                    } else {
                        arrayList2.add(zzfpVar);
                    }
                } else if (c2670tr.e.equals(zzfpVar)) {
                    c2670tr.l(zzfpVar.d);
                } else {
                    this.b.put(strA, c2670tr);
                    concurrentHashMap.remove(strA);
                }
            }
            Iterator it3 = this.a.entrySet().iterator();
            while (it3.hasNext()) {
                Map.Entry entry = (Map.Entry) it3.next();
                if (!hashSet.contains((String) entry.getKey())) {
                    this.b.put((String) entry.getKey(), (C2670tr) entry.getValue());
                    it3.remove();
                }
            }
            Iterator it4 = this.b.entrySet().iterator();
            while (it4.hasNext()) {
                C2670tr c2670tr3 = (C2670tr) ((Map.Entry) it4.next()).getValue();
                boolean z = false;
                c2670tr3.f.set(false);
                c2670tr3.l.set(false);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.x)).booleanValue()) {
                    c2670tr3.h.clear();
                }
                synchronized (c2670tr3) {
                    c2670tr3.b();
                    if (!c2670tr3.h.isEmpty()) {
                        z = true;
                    }
                }
                if (!z) {
                    it4.remove();
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return arrayList2;
    }

    public final synchronized void f(boolean z) {
        try {
            if (z) {
                Iterator it2 = this.a.values().iterator();
                while (it2.hasNext()) {
                    ((C2670tr) it2.next()).k();
                }
            } else {
                Iterator it3 = this.a.values().iterator();
                while (it3.hasNext()) {
                    ((C2670tr) it3.next()).f.set(false);
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0024  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean g(java.lang.String r11, com.google.android.gms.ads.c r12) {
        /*
            r10 = this;
            monitor-enter(r10)
            com.google.android.gms.common.util.a r0 = r10.g     // Catch: java.lang.Throwable -> L37
            long r4 = r0.currentTimeMillis()     // Catch: java.lang.Throwable -> L37
            com.google.android.gms.internal.ads.tr r1 = r10.c(r11, r12)     // Catch: java.lang.Throwable -> L37
            r2 = 0
            if (r1 == 0) goto L24
            monitor-enter(r1)     // Catch: java.lang.Throwable -> L37
            r1.b()     // Catch: java.lang.Throwable -> L26
            java.util.PriorityQueue r3 = r1.h     // Catch: java.lang.Throwable -> L26
            boolean r3 = r3.isEmpty()     // Catch: java.lang.Throwable -> L26
            r6 = 1
            if (r3 != 0) goto L1e
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L37
            r3 = r6
            goto L20
        L1e:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L37
            r3 = r2
        L20:
            if (r3 == 0) goto L24
            r9 = r6
            goto L2a
        L24:
            r9 = r2
            goto L2a
        L26:
            r0 = move-exception
            r11 = r0
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L26
            throw r11     // Catch: java.lang.Throwable -> L37
        L2a:
            r3 = 0
            if (r9 == 0) goto L3a
            long r6 = r0.currentTimeMillis()     // Catch: java.lang.Throwable -> L37
            java.lang.Long r0 = java.lang.Long.valueOf(r6)     // Catch: java.lang.Throwable -> L37
            r6 = r0
            goto L3b
        L37:
            r0 = move-exception
            r11 = r0
            goto L69
        L3a:
            r6 = r3
        L3b:
            com.google.android.gms.internal.ads.Fp r0 = new com.google.android.gms.internal.ads.Fp     // Catch: java.lang.Throwable -> L37
            r7 = 3
            r8 = 0
            r0.<init>(r11, r8, r12, r7)     // Catch: java.lang.Throwable -> L37
            com.google.android.gms.internal.ads.Ar r8 = new com.google.android.gms.internal.ads.Ar     // Catch: java.lang.Throwable -> L37
            r8.<init>(r0)     // Catch: java.lang.Throwable -> L37
            r11 = r1
            com.google.android.gms.internal.ads.Fi r1 = r10.d     // Catch: java.lang.Throwable -> L37
            if (r11 != 0) goto L4e
            r12 = r2
            goto L52
        L4e:
            com.google.android.gms.ads.internal.client.zzfp r12 = r11.e     // Catch: java.lang.Throwable -> L37
            int r12 = r12.d     // Catch: java.lang.Throwable -> L37
        L52:
            if (r11 != 0) goto L55
            goto L59
        L55:
            int r2 = r11.f()     // Catch: java.lang.Throwable -> L37
        L59:
            if (r11 != 0) goto L5f
        L5b:
            r7 = r3
            r3 = r2
            r2 = r12
            goto L64
        L5f:
            java.lang.String r3 = r11.h()     // Catch: java.lang.Throwable -> L37
            goto L5b
        L64:
            r1.m(r2, r3, r4, r6, r7, r8)     // Catch: java.lang.Throwable -> L37
            monitor-exit(r10)
            return r9
        L69:
            monitor-exit(r10)     // Catch: java.lang.Throwable -> L37
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2928zr.g(java.lang.String, com.google.android.gms.ads.c):boolean");
    }
}
