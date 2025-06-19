package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public abstract class m1 extends l1 {
    public boolean d;

    public m1(r1 r1Var) {
        super(r1Var);
        this.c.r++;
    }

    public final void T() {
        if (!this.d) {
            throw new IllegalStateException("Not initialized");
        }
    }

    public final void U() {
        if (this.d) {
            throw new IllegalStateException("Can't initialize twice");
        }
        V();
        this.c.s++;
        this.d = true;
    }

    public abstract void V();
}
