package com.appsflyer.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AFb1lSDK b;

    public /* synthetic */ f(AFb1lSDK aFb1lSDK, int i) {
        this.a = i;
        this.b = aFb1lSDK;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFb1lSDK.getRevenue(this.b);
                break;
            default:
                AFb1lSDK.AFAdRevenueData(this.b);
                break;
        }
    }
}
