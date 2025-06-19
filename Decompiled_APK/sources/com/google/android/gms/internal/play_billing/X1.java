package com.google.android.gms.internal.play_billing;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

/* loaded from: classes2.dex */
public final class X1 extends Z0 {
    public final AtomicReferenceFieldUpdater b;
    public final AtomicReferenceFieldUpdater c;
    public final AtomicReferenceFieldUpdater d;
    public final AtomicReferenceFieldUpdater e;
    public final AtomicReferenceFieldUpdater f;

    public X1(AtomicReferenceFieldUpdater atomicReferenceFieldUpdater, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater3, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater4, AtomicReferenceFieldUpdater atomicReferenceFieldUpdater5) {
        super(9);
        this.b = atomicReferenceFieldUpdater;
        this.c = atomicReferenceFieldUpdater2;
        this.d = atomicReferenceFieldUpdater3;
        this.e = atomicReferenceFieldUpdater4;
        this.f = atomicReferenceFieldUpdater5;
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean B(l2 l2Var, k2 k2Var, k2 k2Var2) {
        return Z0.m(this.d, l2Var, k2Var, k2Var2);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void j(k2 k2Var, k2 k2Var2) {
        this.c.lazySet(k2Var, k2Var2);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final void s(k2 k2Var, Thread thread) {
        this.b.lazySet(k2Var, thread);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean u(l2 l2Var, A1 a1, A1 a12) {
        return Z0.m(this.e, l2Var, a1, a12);
    }

    @Override // com.google.android.gms.internal.play_billing.Z0
    public final boolean w(l2 l2Var, Object obj, Object obj2) {
        return Z0.m(this.f, l2Var, obj, obj2);
    }
}
