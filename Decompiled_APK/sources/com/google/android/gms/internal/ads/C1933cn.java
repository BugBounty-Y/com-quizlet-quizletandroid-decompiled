package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.ads.cn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1933cn extends AbstractC1977dn {
    public final /* synthetic */ int a = 0;
    public final C1765Re b;
    public final Sg c;
    public final Zh d;
    public final C2195in e;
    public final C2923zm f;
    public final Object g;

    public C1933cn(C1765Re c1765Re, Sg sg, Zh zh, C1893bq c1893bq, C2195in c2195in, C2923zm c2923zm) {
        this.b = c1765Re;
        this.c = sg;
        this.d = zh;
        this.g = c1893bq;
        this.e = c2195in;
        this.f = c2923zm;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1977dn
    public final Iq c(C2023eq c2023eq, Bundle bundle, Vp vp, C1849aq c1849aq) {
        C1893bq c1893bq;
        switch (this.a) {
            case 0:
                Sg sg = this.c;
                sg.b = c2023eq;
                sg.c = bundle;
                sg.e = new C2326lq(11, c1849aq, vp, this.e, false);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I3)).booleanValue()) {
                    sg.f = this.f;
                }
                C1765Re c1765Re = this.b.b;
                Sg sg2 = new Sg(sg);
                Os os = new Os(null, 14);
                Zh zh = this.d;
                AbstractC1981ds.w(Zh.class, zh);
                Fi fi = (Fi) this.g;
                AbstractC1981ds.w(Fi.class, fi);
                C2831xg c2831xg = (C2831xg) new C1759Qe(c1765Re, os, fi, new C2147hi(13, (byte) 0), zh, sg2, new Ts(), null, null).t0.zzb();
                return c2831xg.a(c2831xg.b());
            case 1:
                Sg sg3 = this.c;
                sg3.b = c2023eq;
                sg3.c = bundle;
                sg3.e = new C2326lq(11, c1849aq, vp, this.e, false);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I3)).booleanValue()) {
                    sg3.f = this.f;
                }
                C1765Re c1765Re2 = this.b.b;
                Sg sg4 = new Sg(sg3);
                Zh zh2 = this.d;
                AbstractC1981ds.w(Zh.class, zh2);
                C2881yn c2881yn = (C2881yn) this.g;
                AbstractC1981ds.w(C2881yn.class, c2881yn);
                C2831xg c2831xg2 = (C2831xg) new C1813Ze(c1765Re2, new C2147hi(13, (byte) 0), zh2, sg4, new Ts(), c2881yn, null, null).j0.zzb();
                return c2831xg2.a(c2831xg2.b());
            default:
                Sg sg5 = this.c;
                sg5.b = c2023eq;
                sg5.c = bundle;
                sg5.e = new C2326lq(11, c1849aq, vp, this.e, false);
                C2601s7 c2601s7 = AbstractC2773w7.H3;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && (c1893bq = (C1893bq) this.g) != null) {
                    sg5.d = c1893bq;
                }
                if (((Boolean) rVar.c.a(AbstractC2773w7.I3)).booleanValue()) {
                    sg5.f = this.f;
                }
                C1765Re c1765Re3 = this.b.b;
                Sg sg6 = new Sg(sg5);
                Zh zh3 = this.d;
                AbstractC1981ds.w(Zh.class, zh3);
                C2831xg c2831xgZzb = new C1882bf(c1765Re3, new C2147hi(13, (byte) 0), zh3, sg6, new Ts(), null, null).zzb();
                return c2831xgZzb.a(c2831xgZzb.b());
        }
    }

    public C1933cn(C1765Re c1765Re, Sg sg, C2881yn c2881yn, Zh zh, C2195in c2195in, C2923zm c2923zm) {
        this.b = c1765Re;
        this.c = sg;
        this.g = c2881yn;
        this.d = zh;
        this.e = c2195in;
        this.f = c2923zm;
    }

    public C1933cn(C1765Re c1765Re, Fi fi, Sg sg, Zh zh, C2195in c2195in, C2923zm c2923zm) {
        this.b = c1765Re;
        this.g = fi;
        this.c = sg;
        this.d = zh;
        this.e = c2195in;
        this.f = c2923zm;
    }
}
