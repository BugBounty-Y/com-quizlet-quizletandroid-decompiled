package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;

/* loaded from: classes2.dex */
public final class Qo implements Vo {
    public static final C2925zo k = new C2925zo(1, new JSONArray().toString(), new Bundle());
    public final C2227jd a;
    public final ScheduledExecutorService b;
    public final Cn c;
    public final Context d;
    public final C2023eq e;
    public final An f;
    public final C2663tk g;
    public final C1975dl h;
    public final int i;
    public final String j;

    public Qo(C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, String str, Cn cn, Context context, C2023eq c2023eq, An an, C2663tk c2663tk, C1975dl c1975dl, int i) {
        this.a = c2227jd;
        this.b = scheduledExecutorService;
        this.j = str;
        this.c = cn;
        this.d = context;
        this.e = c2023eq;
        this.f = an;
        this.g = c2663tk;
        this.h = c1975dl;
        this.i = i;
    }

    public final Nv a(String str, List list, Bundle bundle, boolean z, boolean z2) {
        Oo oo = new Oo(this, str, list, bundle, z, z2);
        C2227jd c2227jd = this.a;
        Nv nvT = Nv.t(AbstractC2025es.I(oo, c2227jd));
        C2601s7 c2601s7 = AbstractC2773w7.C1;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            nvT = (Nv) AbstractC2025es.O(nvT, ((Long) rVar.c.a(AbstractC2773w7.v1)).longValue(), TimeUnit.MILLISECONDS, this.b);
        }
        return AbstractC2025es.x(nvT, Throwable.class, new C2131h9(str, 3), c2227jd);
    }

    public final void b(Map map, ArrayList arrayList) {
        Iterator it2 = map.entrySet().iterator();
        while (it2.hasNext()) {
            Fn fn = (Fn) ((Map.Entry) it2.next()).getValue();
            String str = fn.a;
            Bundle bundle = this.e.d.m;
            arrayList.add(a(str, Collections.singletonList(fn.e), bundle != null ? bundle.getBundle(str) : null, fn.b, fn.c));
        }
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 32;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        int i = this.i;
        C2925zo c2925zo = k;
        if (i == 2) {
            return AbstractC2025es.E(c2925zo);
        }
        C2023eq c2023eq = this.e;
        if (c2023eq.r) {
            if (!Arrays.asList(((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I1)).split(",")).contains(AbstractC3429b3.d(AbstractC3429b3.e(c2023eq.d)))) {
                return AbstractC2025es.E(c2925zo);
            }
        }
        return AbstractC2025es.I(new C2881yn(this, 25), this.a);
    }
}
