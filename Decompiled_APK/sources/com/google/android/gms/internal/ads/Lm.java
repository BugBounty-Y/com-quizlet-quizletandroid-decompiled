package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Lm implements InterfaceC2751vm {
    public final C1789Ve a;
    public final Context b;
    public final C2406nk c;
    public final C2023eq d;
    public final Executor e;
    public final InterfaceC2544qt f;
    public final Ek g;

    public Lm(C1789Ve c1789Ve, Context context, Executor executor, C2406nk c2406nk, C2023eq c2023eq, InterfaceC2544qt interfaceC2544qt, Ek ek) {
        this.b = context;
        this.a = c1789Ve;
        this.e = executor;
        this.c = c2406nk;
        this.d = c2023eq;
        this.f = interfaceC2544qt;
        this.g = ek;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) {
        Yp yp = vp.s;
        return (yp == null || yp.a == null) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) {
        return AbstractC2025es.N(Tv.b, new C2616sg(this, c1849aq, vp, 4), this.e);
    }
}
