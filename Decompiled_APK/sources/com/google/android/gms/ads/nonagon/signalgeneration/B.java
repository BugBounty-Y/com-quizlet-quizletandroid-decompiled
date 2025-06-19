package com.google.android.gms.ads.nonagon.signalgeneration;

import android.util.Pair;
import androidx.appcompat.app.L;
import com.google.android.gms.internal.ads.AbstractC1911c8;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;

/* loaded from: classes2.dex */
public final class B extends com.google.android.gms.ads.query.a {
    public final A a;
    public final Kk b;
    public final boolean c;
    public final int d;
    public final long e;
    public final Boolean f;

    public B(A a, boolean z, int i, Boolean bool, Kk kk) {
        this.a = a;
        this.c = z;
        this.d = i;
        this.f = bool;
        this.b = kk;
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.e = System.currentTimeMillis();
    }

    @Override // com.google.android.gms.ads.query.a
    public final void a(String str) {
        Pair pair = new Pair("sgf_reason", str);
        Pair pair2 = new Pair("se", "query_g");
        Pair pair3 = new Pair("ad_format", "BANNER");
        Pair pair4 = new Pair("rtype", Integer.toString(6));
        Pair pair5 = new Pair("scar", "true");
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.k.getClass();
        Pair pair6 = new Pair("lat_ms", Long.toString(System.currentTimeMillis() - this.e));
        int i = this.d;
        Pair pair7 = new Pair("sgpc_rn", Integer.toString(i));
        Pair pair8 = new Pair("sgpc_lsu", String.valueOf(this.f));
        boolean z = this.c;
        AbstractC3429b3.f(this.b, "sgpcf", pair, pair2, pair3, pair4, pair5, pair6, pair7, pair8, new Pair("tpc", true != z ? "0" : "1"));
        jVar.k.getClass();
        this.a.a(z, new C(null, str, ((Long) AbstractC1911c8.h.o()).longValue() + System.currentTimeMillis(), i));
    }

    @Override // com.google.android.gms.ads.query.a
    public final void b(L l) {
        Pair pair = new Pair("se", "query_g");
        Pair pair2 = new Pair("ad_format", "BANNER");
        Pair pair3 = new Pair("rtype", Integer.toString(6));
        Pair pair4 = new Pair("scar", "true");
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.k.getClass();
        Pair pair5 = new Pair("lat_ms", Long.toString(System.currentTimeMillis() - this.e));
        int i = this.d;
        Pair pair6 = new Pair("sgpc_rn", Integer.toString(i));
        Pair pair7 = new Pair("sgpc_lsu", String.valueOf(this.f));
        boolean z = this.c;
        AbstractC3429b3.f(this.b, "sgpcs", pair, pair2, pair3, pair4, pair5, pair6, pair7, new Pair("tpc", true != z ? "0" : "1"));
        jVar.k.getClass();
        this.a.a(z, new C(l, "", ((Long) AbstractC1911c8.h.o()).longValue() + System.currentTimeMillis(), i));
    }
}
