package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Cf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1676Cf implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1682Df b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;

    public /* synthetic */ RunnableC1676Cf(C1682Df c1682Df, int i, int i2, int i3) {
        this.a = i3;
        this.b = c1682Df;
        this.c = i;
        this.d = i2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                int i = this.c;
                int i2 = this.d;
                C1682Df c1682Df = this.b;
                c1682Df.b.execute(new RunnableC1676Cf(c1682Df, i, i2, 1));
                break;
            default:
                this.b.A(this.c - 1, this.d);
                break;
        }
    }
}
