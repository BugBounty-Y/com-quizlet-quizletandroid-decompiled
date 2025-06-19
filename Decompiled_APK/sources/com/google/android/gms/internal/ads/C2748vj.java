package com.google.android.gms.internal.ads;

import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.vj, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2748vj implements InterfaceC2189ih {
    public final Yi a;
    public final Zi b;
    public final Executor c;
    public final Xv d;

    public C2748vj(Yi yi, Zi zi, Executor executor, Xv xv) {
        this.a = yi;
        this.b = zi;
        this.c = executor;
        this.d = xv;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        com.google.common.util.concurrent.e eVar;
        com.google.common.util.concurrent.e eVar2;
        C2313ld c2313ld;
        if (this.b.e) {
            Yi yi = this.a;
            C2665tm c2665tmO = yi.o();
            if (c2665tmO == null) {
                synchronized (yi) {
                    eVar = yi.m;
                }
                if (eVar != null && ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r5)).booleanValue()) {
                    synchronized (yi) {
                        eVar2 = yi.m;
                    }
                    synchronized (yi) {
                        c2313ld = yi.n;
                    }
                    if (eVar2 == null || c2313ld == null) {
                        return;
                    }
                    Gv gv = new Gv(AbstractC2330lu.o(new com.google.common.util.concurrent.e[]{eVar2, c2313ld}), false);
                    gv.a(new Qv(0, gv, new C2881yn(this, 17)), this.d);
                    return;
                }
            }
            if (c2665tmO != null) {
                InterfaceC2529qe interfaceC2529qeL = yi.l();
                InterfaceC2529qe interfaceC2529qeM = yi.m();
                if (interfaceC2529qeL == null) {
                    interfaceC2529qeL = interfaceC2529qeM == null ? null : interfaceC2529qeM;
                }
                if (interfaceC2529qeL != null) {
                    this.c.execute(new RunnableC1970dg(interfaceC2529qeL, 3));
                }
            }
        }
    }
}
