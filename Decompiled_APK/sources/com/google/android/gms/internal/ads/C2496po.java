package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.ads.po, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2496po implements Vo {
    public final Context a;
    public final String b;
    public final String c;
    public final long d;
    public final C2917zg e;
    public final C2455oq f;
    public final C2023eq g;
    public final com.google.android.gms.ads.internal.util.C h = com.google.android.gms.ads.internal.j.C.h.d();
    public final Ek i;
    public final Dg j;

    public C2496po(Context context, String str, String str2, C2917zg c2917zg, C2455oq c2455oq, C2023eq c2023eq, Ek ek, Dg dg, long j) {
        this.a = context;
        this.b = str;
        this.c = str2;
        this.e = c2917zg;
        this.f = c2455oq;
        this.g = c2023eq;
        this.i = ek;
        this.j = dg;
        this.d = j;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 12;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final com.google.common.util.concurrent.e zzb() {
        Bundle bundle = new Bundle();
        Ek ek = this.i;
        ConcurrentHashMap concurrentHashMap = ek.a;
        String str = this.b;
        concurrentHashMap.put("seq_num", str);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue()) {
            com.google.android.gms.ads.internal.j.C.k.getClass();
            ek.a("tsacc", String.valueOf(System.currentTimeMillis() - this.d));
            ek.a("foreground", true != com.google.android.gms.ads.internal.util.F.f(this.a) ? "1" : "0");
        }
        C2917zg c2917zg = this.e;
        C2023eq c2023eq = this.g;
        zzm zzmVar = c2023eq.d;
        C1880bd c1880bd = c2917zg.b;
        synchronized (c1880bd.d) {
            long jElapsedRealtime = c1880bd.a.elapsedRealtime();
            c1880bd.j = jElapsedRealtime;
            C2098gd c2098gd = c1880bd.b;
            synchronized (c2098gd.a) {
                c2098gd.d.a(zzmVar, jElapsedRealtime);
            }
        }
        bundle.putAll(this.f.a());
        return AbstractC2025es.E(new C2539qo(this.a, bundle, str, this.c, this.h, c2023eq.f, this.j));
    }
}
