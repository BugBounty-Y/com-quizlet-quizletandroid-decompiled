package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.Tf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1778Tf extends AbstractC2359mg {
    public final Context j;
    public final View k;
    public final InterfaceC2529qe l;
    public final Wp m;
    public final InterfaceC2316lg n;
    public final C1929cj o;
    public final C2490pi p;
    public final InterfaceC2907zC q;
    public final Executor r;
    public com.google.android.gms.ads.internal.client.zzr s;

    public C1778Tf(com.google.android.datatransport.cct.internal.s sVar, Context context, Wp wp, View view, InterfaceC2529qe interfaceC2529qe, InterfaceC2316lg interfaceC2316lg, C1929cj c1929cj, C2490pi c2490pi, InterfaceC2907zC interfaceC2907zC, Executor executor) {
        super(sVar);
        this.j = context;
        this.k = view;
        this.l = interfaceC2529qe;
        this.m = wp;
        this.n = interfaceC2316lg;
        this.o = c1929cj;
        this.p = c2490pi;
        this.q = interfaceC2907zC;
        this.r = executor;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2359mg
    public final void a() {
        this.r.execute(new RunnableC1989e(this, 24));
        super.a();
    }

    public final int b() {
        C2601s7 c2601s7 = AbstractC2773w7.S7;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && this.b.g0) {
            if (!((Boolean) rVar.c.a(AbstractC2773w7.T7)).booleanValue()) {
                return 0;
            }
        }
        return ((Xp) this.a.b.b).c;
    }

    public final Wp c() {
        com.google.android.gms.ads.internal.client.zzr zzrVar = this.s;
        if (zzrVar != null) {
            return zzrVar.i ? new Wp(-3, 0, true) : new Wp(zzrVar.e, zzrVar.b, false);
        }
        Vp vp = this.b;
        if (vp.c0) {
            for (String str : vp.a) {
                if (str == null || !str.contains("FirstParty")) {
                }
            }
            View view = this.k;
            return new Wp(view.getWidth(), view.getHeight(), false);
        }
        return (Wp) vp.r.get(0);
    }
}
