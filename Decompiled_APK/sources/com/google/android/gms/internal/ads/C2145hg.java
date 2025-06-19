package com.google.android.gms.internal.ads;

import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.hg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2145hg implements InterfaceC2617sh, E5, Ph {
    public final Vp a;
    public final C2146hh b;
    public final C2789wh c;
    public final Ch f;
    public final AtomicBoolean d = new AtomicBoolean();
    public final AtomicBoolean e = new AtomicBoolean();
    public final AtomicBoolean g = new AtomicBoolean();

    public C2145hg(Vp vp, C2146hh c2146hh, C2789wh c2789wh, Ch ch) {
        this.a = vp;
        this.b = c2146hh;
        this.c = c2789wh;
        this.f = ch;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        int i = this.a.e;
        if (i == 1) {
            if (d5.j && this.d.compareAndSet(false, true)) {
                this.b.a();
            }
        } else if (i == 4 && d5.j && this.g.compareAndSet(false, true)) {
            this.f.a();
        }
        if (d5.j && this.e.compareAndSet(false, true)) {
            C2789wh c2789wh = this.c;
            synchronized (c2789wh) {
                c2789wh.j1(new C1927ch(10));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final void d() {
        if (this.a.e == 4 && this.d.compareAndSet(false, true)) {
            this.b.a();
        }
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final void o() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final synchronized void s() {
        int i = this.a.e;
        if (i == 1 || i == 4) {
            return;
        }
        if (this.d.compareAndSet(false, true)) {
            this.b.a();
        }
    }
}
