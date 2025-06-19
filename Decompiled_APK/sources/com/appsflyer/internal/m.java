package com.appsflyer.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class m implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AFj1sSDK b;
    public final /* synthetic */ Runnable c;

    public /* synthetic */ m(AFj1sSDK aFj1sSDK, Runnable runnable, int i) {
        this.a = i;
        this.b = aFj1sSDK;
        this.c = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.getCurrencyIso4217Code(this.c);
                break;
            case 1:
                this.b.getRevenue(this.c);
                break;
            case 2:
                this.b.component2(this.c);
                break;
            default:
                this.b.getMonetizationNetwork(this.c);
                break;
        }
    }
}
