package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.h0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3871h0 extends androidx.compose.animation.core.J0 {
    public boolean c;

    public AbstractC3871h0(Y y) {
        super(y);
        ((Y) this.b).D++;
    }

    public abstract boolean T();

    public final void U() {
        if (!this.c) {
            throw new IllegalStateException("Not initialized");
        }
    }

    public final void V() {
        if (this.c) {
            throw new IllegalStateException("Can't initialize twice");
        }
        if (T()) {
            return;
        }
        ((Y) this.b).F.incrementAndGet();
        this.c = true;
    }
}
