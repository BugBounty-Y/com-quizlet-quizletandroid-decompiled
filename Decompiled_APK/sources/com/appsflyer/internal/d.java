package com.appsflyer.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFa1tSDK.getRevenue((AFc1dSDK) this.b);
                break;
            default:
                ((AFd1mSDK) this.b).getMonetizationNetwork();
                break;
        }
    }
}
