package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final class Xo {
    public final Context a;
    public final Set b;
    public final Xv c;
    public final Tq d;
    public final Hk e;
    public long f = 0;
    public int g = 0;

    public Xo(Context context, Xv xv, Set set, Tq tq, Hk hk) {
        this.a = context;
        this.c = xv;
        this.b = set;
        this.d = tq;
        this.e = hk;
    }

    public final Jv a(final Object obj, final Bundle bundle, final boolean z) {
        Pq pqF = LA.f(this.a, 8);
        pqF.zzi();
        Set<Vo> set = this.b;
        final ArrayList arrayList = new ArrayList(set.size());
        List arrayList2 = new ArrayList();
        C2601s7 c2601s7 = AbstractC2773w7.Jb;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zIsEmpty = ((String) rVar.c.a(c2601s7)).isEmpty();
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (!zIsEmpty) {
            arrayList2 = Arrays.asList(((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).split(","));
        }
        List list = arrayList2;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.k.getClass();
        this.f = SystemClock.elapsedRealtime();
        final Bundle bundle2 = new Bundle();
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.h2)).booleanValue() && bundle != null) {
            jVar.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            if (obj instanceof Og) {
                bundle.putLong("client-signals-start", jCurrentTimeMillis);
            } else {
                bundle.putLong("gms-signals-start", jCurrentTimeMillis);
            }
        }
        for (Vo vo : set) {
            if (!list.contains(String.valueOf(vo.zza()))) {
                com.google.android.gms.ads.internal.j.C.k.getClass();
                long jElapsedRealtime = SystemClock.elapsedRealtime();
                com.google.common.util.concurrent.e eVarZzb = vo.zzb();
                eVarZzb.a(new RunnableC1782Ud(this, jElapsedRealtime, vo, bundle2), AbstractC2270kd.g);
                arrayList.add(eVarZzb);
            }
        }
        AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(arrayList);
        Callable callable = new Callable() { // from class: com.google.android.gms.internal.ads.Wo
            @Override // java.util.concurrent.Callable
            public final Object call() {
                Object obj2;
                Bundle bundle3;
                Iterator it2 = arrayList.iterator();
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    obj2 = obj;
                    if (!zHasNext) {
                        break;
                    }
                    Uo uo = (Uo) ((com.google.common.util.concurrent.e) it2.next()).get();
                    if (uo != null) {
                        uo.c(obj2);
                        if (z) {
                            uo.b(obj2);
                        }
                    }
                }
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && (bundle3 = bundle) != null) {
                    com.google.android.gms.ads.internal.j.C.k.getClass();
                    long jCurrentTimeMillis2 = System.currentTimeMillis();
                    boolean z2 = obj2 instanceof Og;
                    Bundle bundle4 = bundle2;
                    if (z2) {
                        bundle3.putLong("client-signals-end", jCurrentTimeMillis2);
                        bundle3.putBundle("client_sig_latency_key", bundle4);
                        return obj2;
                    }
                    bundle3.putLong("gms-signals-end", jCurrentTimeMillis2);
                    bundle3.putBundle("gms_sig_latency_key", bundle4);
                }
                return obj2;
            }
        };
        Jv jv = new Jv(abstractC2330luN, true, false);
        jv.p = new Iv(jv, callable, this.c);
        jv.z();
        if (Uq.a()) {
            AbstractC2096gb.L(jv, this.d, pqF, false);
        }
        return jv;
    }
}
