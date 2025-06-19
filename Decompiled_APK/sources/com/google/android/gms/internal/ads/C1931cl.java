package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.cl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1931cl {
    public final long d;
    public final Context f;
    public final WeakReference g;
    public final C2663tk h;
    public final Xv i;
    public final Executor j;
    public final ScheduledExecutorService k;
    public final Mk l;
    public final VersionInfoParcel m;
    public final C1885bi o;
    public final Uq p;
    public boolean a = false;
    public boolean b = false;
    public boolean c = false;
    public final C2313ld e = new C2313ld();
    public final ConcurrentHashMap n = new ConcurrentHashMap();
    public boolean q = true;

    public C1931cl(Executor executor, Context context, WeakReference weakReference, Xv xv, C2663tk c2663tk, ScheduledExecutorService scheduledExecutorService, Mk mk, VersionInfoParcel versionInfoParcel, C1885bi c1885bi, Uq uq) {
        this.h = c2663tk;
        this.f = context;
        this.g = weakReference;
        this.i = xv;
        this.k = scheduledExecutorService;
        this.j = executor;
        this.l = mk;
        this.m = versionInfoParcel;
        this.o = c1885bi;
        this.p = uq;
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.d = SystemClock.elapsedRealtime();
        d("com.google.android.gms.ads.MobileAds", 0, "", false);
    }

    public final ArrayList a() {
        ArrayList arrayList = new ArrayList();
        ConcurrentHashMap concurrentHashMap = this.n;
        for (String str : concurrentHashMap.keySet()) {
            zzblu zzbluVar = (zzblu) concurrentHashMap.get(str);
            arrayList.add(new zzblu(str, zzbluVar.c, zzbluVar.d, zzbluVar.b));
        }
        return arrayList;
    }

    public final void b() {
        if (!((Boolean) AbstractC1955d8.a.o()).booleanValue()) {
            int i = this.m.c;
            C2601s7 c2601s7 = AbstractC2773w7.Q1;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (i >= ((Integer) rVar.c.a(c2601s7)).intValue() && this.q) {
                if (this.a) {
                    return;
                }
                synchronized (this) {
                    try {
                        if (this.a) {
                            return;
                        }
                        this.l.d();
                        this.o.f();
                        C2313ld c2313ld = this.e;
                        final int i2 = 1;
                        Runnable runnable = new Runnable(this) { // from class: com.google.android.gms.internal.ads.Yk
                            public final /* synthetic */ C1931cl b;

                            {
                                this.b = this;
                            }

                            @Override // java.lang.Runnable
                            public final void run() {
                                switch (i2) {
                                    case 0:
                                        C1931cl c1931cl = this.b;
                                        synchronized (c1931cl) {
                                            try {
                                                if (c1931cl.c) {
                                                    return;
                                                }
                                                com.google.android.gms.ads.internal.j.C.k.getClass();
                                                c1931cl.d("com.google.android.gms.ads.MobileAds", (int) (SystemClock.elapsedRealtime() - c1931cl.d), "Timeout.", false);
                                                c1931cl.l.a("com.google.android.gms.ads.MobileAds", "timeout");
                                                c1931cl.o.zzb("com.google.android.gms.ads.MobileAds", "timeout");
                                                c1931cl.e.d(new Exception());
                                                return;
                                            } finally {
                                            }
                                        }
                                    default:
                                        C1931cl c1931cl2 = this.b;
                                        Mk mk = c1931cl2.l;
                                        synchronized (mk) {
                                            try {
                                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue() && !mk.d) {
                                                    HashMap mapE = mk.e();
                                                    mapE.put("action", "init_finished");
                                                    ArrayList arrayList = mk.b;
                                                    arrayList.add(mapE);
                                                    Iterator it2 = arrayList.iterator();
                                                    while (it2.hasNext()) {
                                                        mk.f.b((Map) it2.next(), false);
                                                    }
                                                    mk.d = true;
                                                }
                                            } finally {
                                            }
                                        }
                                        c1931cl2.o.zze();
                                        c1931cl2.b = true;
                                        return;
                                }
                            }
                        };
                        Xv xv = this.i;
                        c2313ld.a.a(runnable, xv);
                        this.a = true;
                        com.google.common.util.concurrent.e eVarC = c();
                        final int i3 = 0;
                        this.k.schedule(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Yk
                            public final /* synthetic */ C1931cl b;

                            {
                                this.b = this;
                            }

                            @Override // java.lang.Runnable
                            public final void run() {
                                switch (i3) {
                                    case 0:
                                        C1931cl c1931cl = this.b;
                                        synchronized (c1931cl) {
                                            try {
                                                if (c1931cl.c) {
                                                    return;
                                                }
                                                com.google.android.gms.ads.internal.j.C.k.getClass();
                                                c1931cl.d("com.google.android.gms.ads.MobileAds", (int) (SystemClock.elapsedRealtime() - c1931cl.d), "Timeout.", false);
                                                c1931cl.l.a("com.google.android.gms.ads.MobileAds", "timeout");
                                                c1931cl.o.zzb("com.google.android.gms.ads.MobileAds", "timeout");
                                                c1931cl.e.d(new Exception());
                                                return;
                                            } finally {
                                            }
                                        }
                                    default:
                                        C1931cl c1931cl2 = this.b;
                                        Mk mk = c1931cl2.l;
                                        synchronized (mk) {
                                            try {
                                                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c2)).booleanValue() && !mk.d) {
                                                    HashMap mapE = mk.e();
                                                    mapE.put("action", "init_finished");
                                                    ArrayList arrayList = mk.b;
                                                    arrayList.add(mapE);
                                                    Iterator it2 = arrayList.iterator();
                                                    while (it2.hasNext()) {
                                                        mk.f.b((Map) it2.next(), false);
                                                    }
                                                    mk.d = true;
                                                }
                                            } finally {
                                            }
                                        }
                                        c1931cl2.o.zze();
                                        c1931cl2.b = true;
                                        return;
                                }
                            }
                        }, ((Long) rVar.c.a(AbstractC2773w7.S1)).longValue(), TimeUnit.SECONDS);
                        eVarC.a(new Qv(0, eVarC, new C2881yn(this, 19)), xv);
                        return;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }
        if (this.a) {
            return;
        }
        d("com.google.android.gms.ads.MobileAds", 0, "", true);
        this.e.c(Boolean.FALSE);
        this.a = true;
        this.b = true;
    }

    public final synchronized com.google.common.util.concurrent.e c() {
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        String str = jVar.h.d().n().e;
        if (!TextUtils.isEmpty(str)) {
            return AbstractC2025es.E(str);
        }
        C2313ld c2313ld = new C2313ld();
        com.google.android.gms.ads.internal.util.C cD = jVar.h.d();
        cD.c.add(new Qv(26, this, c2313ld));
        return c2313ld;
    }

    public final void d(String str, int i, String str2, boolean z) {
        this.n.put(str, new zzblu(str, i, str2, z));
    }
}
