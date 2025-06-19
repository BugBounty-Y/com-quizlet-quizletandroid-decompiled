package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zzt;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class Ah extends AbstractC2863yB implements InterfaceC2189ih, InterfaceC2832xh {
    public final Vp c;
    public final AtomicBoolean d;
    public final C1849aq e;

    public Ah(Set set, Vp vp, C1849aq c1849aq) {
        super(set);
        this.d = new AtomicBoolean();
        this.c = vp;
        this.e = c1849aq;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        int i = this.c.b;
        if (i == 2 || i == 5 || i == 4 || i == 6 || i == 7) {
            k1();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2832xh
    public final void h() {
        if (this.c.b == 1) {
            k1();
        }
    }

    public final void k1() {
        zzt zztVar;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Q7)).booleanValue() && this.d.compareAndSet(false, true) && (zztVar = this.c.e0) != null && zztVar.a == 3) {
            j1(new C2881yn(zztVar, 14));
        }
    }
}
