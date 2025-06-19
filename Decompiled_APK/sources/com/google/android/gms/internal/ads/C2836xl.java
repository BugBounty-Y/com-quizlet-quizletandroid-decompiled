package com.google.android.gms.internal.ads;

import android.content.Context;

/* renamed from: com.google.android.gms.internal.ads.xl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2836xl implements Jh, InterfaceC2618si, InterfaceC2617sh {
    public final Context a;
    public final Hk b;

    public C2836xl(Context context, Hk hk) {
        this.a = context;
        this.b = hk;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(com.google.android.gms.ads.nonagon.signalgeneration.q qVar) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H4)).booleanValue()) {
            c(this.a);
        }
    }

    public final void c(Context context) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E4)).booleanValue()) {
            AbstractC2270kd.a.execute(new RunnableC2793wl(0, this, context));
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G4)).booleanValue()) {
            c(this.a);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I4)).booleanValue()) {
            c(this.a);
        }
    }
}
