package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class M0 implements Runnable {
    public final /* synthetic */ L0 a;
    public final /* synthetic */ L0 b;
    public final /* synthetic */ long c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ O0 e;

    public M0(O0 o0, L0 l0, L0 l02, long j, boolean z) {
        this.a = l0;
        this.b = l02;
        this.c = j;
        this.d = z;
        this.e = o0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.e.W(this.a, this.b, this.c, this.d, null);
    }
}
