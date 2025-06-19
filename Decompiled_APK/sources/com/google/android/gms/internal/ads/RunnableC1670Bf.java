package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Bf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1670Bf implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1682Df b;

    public /* synthetic */ RunnableC1670Bf(C1682Df c1682Df, int i) {
        this.a = i;
        this.b = c1682Df;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C1682Df c1682Df = this.b;
                c1682Df.b.execute(new RunnableC1670Bf(c1682Df, 1));
                break;
            default:
                this.b.o();
                break;
        }
    }
}
