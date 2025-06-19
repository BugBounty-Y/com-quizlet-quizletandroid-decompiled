package com.appsflyer;

import com.appsflyer.internal.AFg1gSDK;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AFg1gSDK[] b;

    public /* synthetic */ b(AFg1gSDK[] aFg1gSDKArr, int i) {
        this.a = i;
        this.b = aFg1gSDKArr;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                AFLogger.getMediationNetwork(this.b);
                break;
            default:
                AFLogger.getCurrencyIso4217Code(this.b);
                break;
        }
    }
}
