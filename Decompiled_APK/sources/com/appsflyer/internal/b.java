package com.appsflyer.internal;

import com.appsflyer.internal.AFd1vSDK;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements AFd1vSDK.AFa1ySDK, AFf1mSDK, com.google.android.gms.tasks.d {
    public final /* synthetic */ Object a;

    public /* synthetic */ b(Object obj) {
        this.a = obj;
    }

    @Override // com.appsflyer.internal.AFd1vSDK.AFa1ySDK
    public void onConfigurationChanged(boolean z) {
        ((AFa1tSDK) this.a).getMonetizationNetwork(z);
    }

    @Override // com.appsflyer.internal.AFf1mSDK
    public void onRemoteConfigUpdateFinished(AFf1nSDK aFf1nSDK) {
        ((AFa1tSDK) this.a).getCurrencyIso4217Code(aFf1nSDK);
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        AFb1cSDK.AFAdRevenueData((AFb1cSDK) this.a, (com.google.android.gms.appset.b) obj);
    }
}
