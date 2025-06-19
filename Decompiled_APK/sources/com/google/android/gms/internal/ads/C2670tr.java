package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.ClientApi;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzfp;
import com.google.android.gms.internal.measurement.C3083y1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import java.util.PriorityQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.tr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2670tr {
    public final ClientApi a;
    public final Context b;
    public final int c;
    public final InterfaceC2825xa d;
    public zzfp e;
    public final com.google.android.gms.ads.internal.client.N g;
    public final PriorityQueue h;
    public final C2713ur i;
    public final ScheduledExecutorService k;
    public Fi n;
    public final com.google.android.gms.common.util.a o;
    public final Ar p;
    public final /* synthetic */ int q;
    public final AtomicBoolean f = new AtomicBoolean(true);
    public final AtomicBoolean j = new AtomicBoolean(false);
    public final AtomicBoolean l = new AtomicBoolean(true);
    public final AtomicBoolean m = new AtomicBoolean(false);

    public C2670tr(ClientApi clientApi, Context context, int i, InterfaceC2825xa interfaceC2825xa, zzfp zzfpVar, com.google.android.gms.ads.internal.client.N n, ScheduledExecutorService scheduledExecutorService, C2713ur c2713ur, com.google.android.gms.common.util.a aVar, int i2) {
        this.q = i2;
        this.a = clientApi;
        this.b = context;
        this.c = i;
        this.d = interfaceC2825xa;
        this.e = zzfpVar;
        this.g = n;
        this.h = new PriorityQueue(Math.max(1, zzfpVar.d), new Cr(this, 0));
        this.k = scheduledExecutorService;
        this.i = c2713ur;
        this.o = aVar;
        this.p = new Ar(new Fp(zzfpVar.a, false, com.google.android.gms.ads.c.a(this.e.b), 3));
    }

    public static void i(C2670tr c2670tr, zze zzeVar) {
        synchronized (c2670tr) {
            c2670tr.j.set(false);
            int i = zzeVar.a;
            if (i != 1 && i != 8 && i != 10 && i != 11) {
                c2670tr.c(true);
                return;
            }
            zzfp zzfpVar = c2670tr.e;
            com.google.android.gms.ads.internal.util.client.i.g("Preloading " + zzfpVar.b + ", for adUnitId:" + zzfpVar.a + ", Ad load failed. Stop preloading due to non-retriable error:");
            c2670tr.f.set(false);
        }
    }

    public final synchronized void a() {
        AtomicBoolean atomicBoolean = this.m;
        if (atomicBoolean.get() && this.h.isEmpty()) {
            atomicBoolean.set(false);
            com.google.android.gms.ads.internal.util.F.l.post(new Dr(this, 2));
            this.k.execute(new Dr(this, 3));
        }
    }

    public final synchronized void b() {
        Iterator it2 = this.h.iterator();
        while (it2.hasNext()) {
            Br br = (Br) it2.next();
            if (br.c.currentTimeMillis() >= br.b + br.d) {
                it2.remove();
            }
        }
    }

    public final synchronized void c(boolean z) {
        C2713ur c2713ur = this.i;
        if (c2713ur.c <= Math.max(c2713ur.d, ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.C)).intValue()) || c2713ur.e < c2713ur.b) {
            if (z) {
                double d = c2713ur.e;
                c2713ur.e = Math.min((long) (d + d), c2713ur.b);
                c2713ur.c++;
            }
            ScheduledExecutorService scheduledExecutorService = this.k;
            Dr dr = new Dr(this, 0);
            double d2 = c2713ur.e;
            double d3 = 0.2d * d2;
            long j = (long) (d2 + d3);
            scheduledExecutorService.schedule(dr, ((long) (d2 - d3)) + ((long) (c2713ur.f.nextDouble() * ((j - r4) + 1))), TimeUnit.MILLISECONDS);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x0019, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.k(3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0026, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.k(3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x000c, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.k(3);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.ads.internal.client.s0 d(java.lang.Object r2) {
        /*
            r1 = this;
            int r0 = r1.q
            switch(r0) {
                case 0: goto L1f;
                case 1: goto L12;
                default: goto L5;
            }
        L5:
            com.google.android.gms.internal.ads.oc r2 = (com.google.android.gms.internal.ads.InterfaceC2441oc) r2
            com.google.android.gms.ads.internal.client.s0 r2 = r2.a()     // Catch: android.os.RemoteException -> Lc
            goto L11
        Lc:
            r2 = 3
            com.google.android.gms.ads.internal.util.client.i.k(r2)
            r2 = 0
        L11:
            return r2
        L12:
            com.google.android.gms.ads.internal.client.K r2 = (com.google.android.gms.ads.internal.client.K) r2
            com.google.android.gms.ads.internal.client.s0 r2 = r2.n()     // Catch: android.os.RemoteException -> L19
            goto L1e
        L19:
            r2 = 3
            com.google.android.gms.ads.internal.util.client.i.k(r2)
            r2 = 0
        L1e:
            return r2
        L1f:
            com.google.android.gms.internal.ads.Y5 r2 = (com.google.android.gms.internal.ads.Y5) r2
            com.google.android.gms.ads.internal.client.s0 r2 = r2.f()     // Catch: android.os.RemoteException -> L26
            goto L2b
        L26:
            r2 = 3
            com.google.android.gms.ads.internal.util.client.i.k(r2)
            r2 = 0
        L2b:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2670tr.d(java.lang.Object):com.google.android.gms.ads.internal.client.s0");
    }

    public final C1985dw e(Context context) {
        switch (this.q) {
            case 0:
                C1985dw c1985dw = new C1985dw();
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
                com.google.android.gms.ads.internal.client.zzr zzrVarA = com.google.android.gms.ads.internal.client.zzr.a();
                zzfp zzfpVar = this.e;
                int i = this.c;
                com.google.android.gms.ads.internal.client.K kV1 = this.a.v1(bVar, zzrVarA, zzfpVar.a, this.d, i);
                if (kV1 != null) {
                    try {
                        BinderC2625sp binderC2625sp = (BinderC2625sp) kV1;
                        binderC2625sp.g3(new BinderC2627sr(this, c1985dw, this.e));
                        binderC2625sp.I2(this.e.c);
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("Failed to load app open ad.", e);
                        c1985dw.h(new zzfjt());
                    }
                } else {
                    c1985dw.h(new zzfjt());
                }
                return c1985dw;
            case 1:
                C1985dw c1985dw2 = new C1985dw();
                com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(context);
                com.google.android.gms.ads.internal.client.zzr zzrVar = new com.google.android.gms.ads.internal.client.zzr();
                zzfp zzfpVar2 = this.e;
                int i2 = this.c;
                com.google.android.gms.ads.internal.client.K kF0 = this.a.F0(bVar2, zzrVar, zzfpVar2.a, this.d, i2);
                if (kF0 != null) {
                    try {
                        ((On) kF0).Y0(this.e.c, new BinderC2756vr(this, c1985dw2, (On) kF0));
                    } catch (RemoteException e2) {
                        com.google.android.gms.ads.internal.util.client.i.i("Failed to load interstitial ad.", e2);
                        c1985dw2.h(new zzfjt());
                    }
                } else {
                    c1985dw2.h(new zzfjt());
                }
                return c1985dw2;
            default:
                C1985dw c1985dw3 = new C1985dw();
                com.google.android.gms.dynamic.b bVar3 = new com.google.android.gms.dynamic.b(context);
                zzfp zzfpVar3 = this.e;
                int i3 = this.c;
                InterfaceC2441oc interfaceC2441ocX2 = this.a.x2(bVar3, zzfpVar3.a, this.d, i3);
                Fr fr = new Fr(this, c1985dw3, (Sp) interfaceC2441ocX2);
                if (interfaceC2441ocX2 != null) {
                    try {
                        ((Sp) interfaceC2441ocX2).Z2(this.e.c, fr);
                    } catch (RemoteException unused) {
                        com.google.android.gms.ads.internal.util.client.i.h("Failed to load rewarded ad.");
                        c1985dw3.h(new zzfjt());
                    }
                } else {
                    c1985dw3.h(new zzfjt());
                }
                return c1985dw3;
        }
    }

    public final synchronized int f() {
        return this.h.size();
    }

    public final synchronized Object g() {
        try {
            C2713ur c2713ur = this.i;
            c2713ur.e = c2713ur.a;
            c2713ur.c = 0L;
            PriorityQueue priorityQueue = this.h;
            Br br = (Br) priorityQueue.poll();
            this.m.set(br != null);
            if (br == null) {
                br = null;
            } else if (!priorityQueue.isEmpty()) {
                Br br2 = (Br) priorityQueue.peek();
                com.google.android.gms.ads.c cVarA = com.google.android.gms.ads.c.a(this.e.b);
                com.google.android.gms.ads.internal.client.s0 s0VarD = d(br.a);
                String str = !(s0VarD instanceof Ug) ? null : ((Ug) s0VarD).d;
                if (br2 != null && cVarA != null && str != null && br2.b < br.b) {
                    this.n.z("poll_ad", "psvroc_ts", this.o.currentTimeMillis(), this.e.d, f(), str, this.p);
                }
            }
            j();
            if (br == null) {
                return null;
            }
            return br.a;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized String h() {
        String str;
        Object obj;
        synchronized (this) {
            Br br = (Br) this.h.peek();
            str = null;
            obj = br == null ? null : br.a;
        }
        return str;
        com.google.android.gms.ads.internal.client.s0 s0VarD = obj == null ? null : d(obj);
        if (s0VarD instanceof Ug) {
            str = ((Ug) s0VarD).d;
        }
        return str;
    }

    public final synchronized void j() {
        Activity activity;
        C1985dw c1985dwE;
        try {
            b();
            a();
            AtomicBoolean atomicBoolean = this.j;
            if (!atomicBoolean.get() && this.f.get() && this.h.size() < this.e.d) {
                atomicBoolean.set(true);
                C3083y1 c3083y1 = com.google.android.gms.ads.internal.j.C.g;
                synchronized (c3083y1.c) {
                    K5 k5 = (K5) c3083y1.d;
                    activity = k5 != null ? k5.a : null;
                }
                if (activity == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Empty activity context at preloading: ".concat(String.valueOf(this.e.a)));
                    c1985dwE = e(this.b);
                } else {
                    c1985dwE = e(activity);
                }
                c1985dwE.a(new Qv(0, c1985dwE, new S4(this, 28)), this.k);
            }
        } catch (Throwable th) {
            throw th;
        } finally {
        }
    }

    public final synchronized void k() {
        this.f.set(true);
        this.l.set(true);
        this.k.submit(new Dr(this, 0));
    }

    public final void l(int i) {
        com.google.android.gms.common.internal.u.b(i > 0);
        com.google.android.gms.ads.c cVarA = com.google.android.gms.ads.c.a(this.e.b);
        int i2 = this.e.d;
        synchronized (this) {
            try {
                zzfp zzfpVar = this.e;
                this.e = new zzfp(zzfpVar.a, zzfpVar.b, zzfpVar.c, i > 0 ? i : zzfpVar.d);
                PriorityQueue priorityQueue = this.h;
                if (priorityQueue.size() > i) {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u)).booleanValue()) {
                        ArrayList arrayList = new ArrayList();
                        for (int i3 = 0; i3 < i; i3++) {
                            Br br = (Br) priorityQueue.poll();
                            if (br != null) {
                                arrayList.add(br);
                            }
                        }
                        priorityQueue.clear();
                        priorityQueue.addAll(arrayList);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        Fi fi = this.n;
        if (fi == null || cVarA == null) {
            return;
        }
        long jCurrentTimeMillis = this.o.currentTimeMillis();
        String str = this.e.a;
        Fi fiA = ((Hk) fi.b).a();
        fiA.o("action", "cache_resize");
        fiA.o("cs_ts", Long.toString(jCurrentTimeMillis));
        fiA.o("app", (String) fi.c);
        fiA.o("orig_ma", Integer.toString(i2));
        fiA.o("max_ads", Integer.toString(i));
        fiA.o("ad_format", cVarA.name().toLowerCase(Locale.ENGLISH));
        fiA.o("ad_unit_id", str);
        fiA.x();
    }

    public final synchronized void m(Object obj) {
        com.google.android.gms.common.util.a aVar = this.o;
        Br br = new Br(obj, aVar);
        this.h.add(br);
        com.google.android.gms.ads.internal.client.s0 s0VarD = d(obj);
        long jCurrentTimeMillis = aVar.currentTimeMillis();
        com.google.android.gms.ads.internal.util.F.l.post(new Dr(this, 1));
        com.android.volley.i iVar = new com.android.volley.i(this, jCurrentTimeMillis, s0VarD);
        ScheduledExecutorService scheduledExecutorService = this.k;
        scheduledExecutorService.execute(iVar);
        scheduledExecutorService.schedule(new Dr(this, 0), (br.d + Math.min(Math.max(((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.y)).longValue(), -900000L), 10000L)) - (aVar.currentTimeMillis() - br.b), TimeUnit.MILLISECONDS);
    }
}
