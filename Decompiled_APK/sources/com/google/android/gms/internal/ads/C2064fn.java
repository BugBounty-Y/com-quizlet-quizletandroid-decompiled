package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.widget.FrameLayout;

/* renamed from: com.google.android.gms.internal.ads.fn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2064fn extends AbstractC1977dn {
    public final C1765Re a;
    public final Sg b;
    public final C2881yn c;
    public final Zh d;
    public final Fi e;
    public final Gh f;
    public final FrameLayout g;
    public final Rh h;
    public final C2195in i;
    public final C2923zm j;

    public C2064fn(C1765Re c1765Re, Sg sg, C2881yn c2881yn, Zh zh, Fi fi, Gh gh, FrameLayout frameLayout, Rh rh, C2195in c2195in, C2923zm c2923zm) {
        this.a = c1765Re;
        this.b = sg;
        this.c = c2881yn;
        this.d = zh;
        this.e = fi;
        this.f = gh;
        this.g = frameLayout;
        this.h = rh;
        this.i = c2195in;
        this.j = c2923zm;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1977dn
    public final Iq c(C2023eq c2023eq, Bundle bundle, Vp vp, C1849aq c1849aq) {
        Sg sg = this.b;
        sg.b = c2023eq;
        sg.c = bundle;
        sg.e = new C2326lq(11, c1849aq, vp, this.i, false);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I3)).booleanValue()) {
            sg.f = this.j;
        }
        C1765Re c1765Re = this.a.b;
        Sg sg2 = new Sg(sg);
        C1732Mb c1732Mb = new C1732Mb(16, this.f, this.h);
        Os os = new Os(this.g, 14);
        Zh zh = this.d;
        AbstractC1981ds.w(Zh.class, zh);
        C2881yn c2881yn = this.c;
        AbstractC1981ds.w(C2881yn.class, c2881yn);
        Ts ts = new Ts();
        Fi fi = this.e;
        AbstractC1981ds.w(Fi.class, fi);
        C2831xg c2831xg = (C2831xg) new C1789Ve(c1765Re, os, fi, new C2147hi(13, (byte) 0), zh, sg2, ts, c2881yn, c1732Mb, null, null).t0.zzb();
        return c2831xg.a(c2831xg.b());
    }
}
