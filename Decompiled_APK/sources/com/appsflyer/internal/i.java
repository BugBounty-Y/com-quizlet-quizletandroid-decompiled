package com.appsflyer.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AFd1uSDK b;

    public /* synthetic */ i(AFd1uSDK aFd1uSDK, int i) {
        this.a = i;
        this.b = aFd1uSDK;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFd1uSDK.AFAdRevenueData(this.b);
                break;
            case 1:
                AFd1uSDK.getMediationNetwork(this.b);
                break;
            default:
                AFd1uSDK.getMonetizationNetwork(this.b);
                break;
        }
    }
}
