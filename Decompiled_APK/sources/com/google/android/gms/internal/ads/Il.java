package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class Il implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Jl b;

    public /* synthetic */ Il(Jl jl, int i) {
        this.a = i;
        this.b = jl;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a();
                break;
            default:
                this.b.a();
                break;
        }
    }
}
