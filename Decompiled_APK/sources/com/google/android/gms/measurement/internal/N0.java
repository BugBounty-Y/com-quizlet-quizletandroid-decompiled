package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class N0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ O0 b;

    public /* synthetic */ N0(O0 o0, int i) {
        this.a = i;
        this.b = o0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                O0 o0 = this.b;
                o0.f = o0.k;
                break;
            default:
                this.b.k = null;
                break;
        }
    }
}
