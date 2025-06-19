package com.google.android.gms.internal.ads;

import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Wx {
    public static final Wx b = new Wx();
    public final AtomicReference a = new AtomicReference(new C2291ky(new Ps()));

    public final synchronized void a(C2163hy c2163hy) {
        AtomicReference atomicReference = this.a;
        Ps ps = new Ps((C2291ky) atomicReference.get());
        ps.b(c2163hy);
        atomicReference.set(new C2291ky(ps));
    }

    public final synchronized void b(InterfaceC2334ly interfaceC2334ly) {
        AtomicReference atomicReference = this.a;
        Ps ps = new Ps((C2291ky) atomicReference.get());
        ps.r(interfaceC2334ly);
        atomicReference.set(new C2291ky(ps));
    }
}
