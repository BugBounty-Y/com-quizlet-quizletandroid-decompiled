package com.google.android.gms.internal.play_billing;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* renamed from: com.google.android.gms.internal.play_billing.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3795f0 extends Z0 {
    public final AtomicReferenceFieldUpdater b;
    public final AtomicReferenceFieldUpdater c;
    public final AtomicReferenceFieldUpdater d;
    public final AtomicReferenceFieldUpdater e;
    public final AtomicReferenceFieldUpdater f;

    public C3795f0(AtomicReferenceFieldUpdater atomicReferenceFieldUpdater, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater3, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater4, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater5) {
        super(7);
        this.b = atomicReferenceFieldUpdater;
        this.c = atomicReferenceFieldUpdater2;
        this.d = atomicReferenceFieldUpdater3;
        this.e = atomicReferenceFieldUpdater4;
        this.f = atomicReferenceFieldUpdater5;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean A(AbstractC3816m0 abstractC3816m0, C3792e0 c3792e0, C3792e0 c3792e02) {
        return Z0.l(this.e, abstractC3816m0, c3792e0, c3792e02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean E(AbstractC3816m0 abstractC3816m0, Object obj, Object obj2) {
        return Z0.l(this.f, abstractC3816m0, obj, obj2);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean G(AbstractC3816m0 abstractC3816m0, C3813l0 c3813l0, C3813l0 c3813l02) {
        return Z0.l(this.d, abstractC3816m0, c3813l0, c3813l02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3792e0 e(AbstractC3816m0 abstractC3816m0) {
        return (C3792e0) this.e.getAndSet(abstractC3816m0, C3792e0.d);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final C3813l0 p(AbstractC3816m0 abstractC3816m0) {
        return (C3813l0) this.d.getAndSet(abstractC3816m0, C3813l0.c);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void t(C3813l0 c3813l0, C3813l0 c3813l02) {
        this.c.lazySet(c3813l0, c3813l02);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void v(C3813l0 c3813l0, Thread thread) {
        this.b.lazySet(c3813l0, thread);
    }
}
