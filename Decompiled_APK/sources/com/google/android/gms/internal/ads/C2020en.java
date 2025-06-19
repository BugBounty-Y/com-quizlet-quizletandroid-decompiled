package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.ads.en, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2020en extends AbstractC1977dn {
    public final C1765Re a;
    public final Sg b;
    public final Zh c;
    public final C2195in d;
    public final C2923zm e;

    public C2020en(C1765Re c1765Re, Sg sg, Zh zh, C2195in c2195in, C2923zm c2923zm) {
        this.a = c1765Re;
        this.b = sg;
        this.c = zh;
        this.d = c2195in;
        this.e = c2923zm;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1977dn
    public final Iq c(C2023eq c2023eq, Bundle bundle, Vp vp, C1849aq c1849aq) {
        Sg sg = this.b;
        sg.b = c2023eq;
        sg.c = bundle;
        sg.e = new C2326lq(11, c1849aq, vp, this.d, false);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I3)).booleanValue()) {
            sg.f = this.e;
        }
        C1765Re c1765Re = this.a.b;
        Sg sg2 = new Sg(sg);
        Zh zh = this.c;
        AbstractC1981ds.w(Zh.class, zh);
        C2831xg c2831xgZzb = new C1777Te(c1765Re, new C2147hi(13, (byte) 0), zh, sg2, new Ts(), null, null).zzb();
        return c2831xgZzb.a(c2831xgZzb.b());
    }
}
