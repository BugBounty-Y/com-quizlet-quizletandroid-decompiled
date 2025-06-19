package com.google.android.gms.internal.ads;

import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.vg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2745vg implements com.google.android.gms.ads.internal.overlay.j {
    public final C2489ph a;
    public final AtomicBoolean b = new AtomicBoolean(false);
    public final AtomicBoolean c = new AtomicBoolean(false);

    public C2745vg(C2489ph c2489ph) {
        this.a = c2489ph;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
        this.a.j1(new C1927ch(5));
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        this.b.set(true);
        AtomicBoolean atomicBoolean = this.c;
        if (atomicBoolean.get()) {
            return;
        }
        atomicBoolean.set(true);
        this.a.j1(new C1927ch(3));
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
        AtomicBoolean atomicBoolean = this.c;
        if (atomicBoolean.get()) {
            return;
        }
        atomicBoolean.set(true);
        this.a.j1(new C1927ch(3));
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }
}
