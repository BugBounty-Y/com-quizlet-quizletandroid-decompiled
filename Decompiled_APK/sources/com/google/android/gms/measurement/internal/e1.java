package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class e1 implements Runnable {
    public final long a;
    public final long b;
    public final /* synthetic */ androidx.work.impl.model.e c;

    public e1(androidx.work.impl.model.e eVar, long j, long j2) {
        this.c = eVar;
        this.a = j;
        this.b = j2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        X x = ((Y) ((g1) this.c.c).b).j;
        Y.k(x);
        x.c0(new com.google.android.gms.common.api.internal.w(this, 5));
    }
}
