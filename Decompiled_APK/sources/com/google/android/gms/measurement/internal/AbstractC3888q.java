package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3888q extends AbstractC3886p {
    public boolean c;

    public AbstractC3888q(Y y) {
        super(y);
        ((Y) this.b).D++;
    }

    @Override // androidx.compose.animation.core.J0
    public final void Q() {
        if (!this.c) {
            throw new IllegalStateException("Not initialized");
        }
    }

    public final void T() {
        if (this.c) {
            throw new IllegalStateException("Can't initialize twice");
        }
        if (U()) {
            return;
        }
        ((Y) this.b).F.incrementAndGet();
        this.c = true;
    }

    public abstract boolean U();
}
