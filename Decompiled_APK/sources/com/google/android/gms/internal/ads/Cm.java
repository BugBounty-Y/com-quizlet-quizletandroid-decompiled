package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Cm implements InterfaceC2751vm {
    public final C1777Te a;
    public final C2406nk b;
    public final C2023eq c;
    public final Executor d;
    public final VersionInfoParcel e;
    public final C2475p9 f;
    public final boolean g = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T8)).booleanValue();
    public final BinderC2408nm h;
    public final Ek i;
    public final Hk j;

    public Cm(C1777Te c1777Te, Context context, Executor executor, C2406nk c2406nk, C2023eq c2023eq, VersionInfoParcel versionInfoParcel, C2475p9 c2475p9, BinderC2408nm binderC2408nm, Ek ek, Hk hk) {
        this.a = c1777Te;
        this.d = executor;
        this.b = c2406nk;
        this.c = c2023eq;
        this.e = versionInfoParcel;
        this.f = c2475p9;
        this.h = binderC2408nm;
        this.i = ek;
        this.j = hk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        Yp yp = vp.s;
        return (yp == null || yp.a == null) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        C2147hi c2147hi = new C2147hi(12, (byte) 0);
        Tv tv = Tv.b;
        C2616sg c2616sg = new C2616sg(this, vp, c1849aq, c2147hi, 3);
        Executor executor = this.d;
        C2846xv c2846xvN = AbstractC2025es.N(tv, c2616sg, executor);
        c2846xvN.a(new C4(c2147hi, 3), executor);
        return c2846xvN;
    }
}
