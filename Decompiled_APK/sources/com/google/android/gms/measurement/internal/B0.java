package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class B0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C3881m0 b;
    public final /* synthetic */ long c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ D0 e;

    public /* synthetic */ B0(D0 d0, C3881m0 c3881m0, long j, boolean z, int i) {
        this.a = i;
        this.b = c3881m0;
        this.c = j;
        this.d = z;
        this.e = d0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C3881m0 c3881m0 = this.b;
                D0 d0 = this.e;
                d0.l0(c3881m0);
                D0.V(d0, c3881m0, this.c, this.d);
                break;
            default:
                C3881m0 c3881m02 = this.b;
                D0 d02 = this.e;
                d02.l0(c3881m02);
                D0.V(d02, c3881m02, this.c, this.d);
                break;
        }
    }
}
