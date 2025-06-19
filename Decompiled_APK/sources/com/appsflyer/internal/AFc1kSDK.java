package com.appsflyer.internal;

import com.appsflyer.AppsFlyerConsent;

/* loaded from: classes.dex */
public final class AFc1kSDK {
    public String AFAdRevenueData;
    public boolean areAllFieldsValid;
    public boolean component1;
    public AppsFlyerConsent component2;
    public AFh1oSDK component3;
    public AFd1hSDK component4;
    public String getCurrencyIso4217Code;
    public String getMediationNetwork;
    public AFb1qSDK getMonetizationNetwork;
    public AFb1uSDK getRevenue;
    public AFb1gSDK toString;

    public final boolean AFAdRevenueData() {
        return this.component1;
    }

    public final boolean getMonetizationNetwork() {
        return this.areAllFieldsValid;
    }

    public final synchronized void getRevenue(AFd1hSDK aFd1hSDK) {
        this.component4 = aFd1hSDK;
    }
}
