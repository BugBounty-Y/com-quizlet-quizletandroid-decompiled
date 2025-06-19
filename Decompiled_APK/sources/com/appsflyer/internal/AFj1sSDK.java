package com.appsflyer.internal;

import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.RunnableC0131h;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerProperties;
import com.appsflyer.internal.AFj1qSDK;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class AFj1sSDK {
    public final List<AFj1qSDK> getCurrencyIso4217Code = new ArrayList();
    public final AFc1dSDK getMediationNetwork;

    public AFj1sSDK(AFc1dSDK aFc1dSDK) {
        this.getMediationNetwork = aFc1dSDK;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void component2(Runnable runnable) {
        AFj1zSDK aFj1zSDK = new AFj1zSDK(this.getMediationNetwork.getRevenue(), this.getMediationNetwork.getMonetizationNetwork(), AFj1ySDK.INSTAGRAM, runnable, new m(this, runnable, 3));
        getMediationNetwork(aFj1zSDK);
        aFj1zSDK.getRevenue(this.getMediationNetwork.AFInAppEventType().getMonetizationNetwork);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ void getCurrencyIso4217Code() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void getMonetizationNetwork(AFi1aSDK aFi1aSDK, Runnable runnable) {
        AFc1qSDK aFc1qSDKComponent2 = this.getMediationNetwork.component2();
        int iAFAdRevenueData = this.getMediationNetwork.getRevenue().getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0);
        boolean mediationNetwork = aFc1qSDKComponent2.getMediationNetwork(AppsFlyerProperties.NEW_REFERRER_SENT, false);
        boolean z = aFi1aSDK.component4 == AFj1qSDK.AFa1ySDK.NOT_STARTED;
        if (iAFAdRevenueData == 1) {
            if (z || mediationNetwork) {
                runnable.run();
            }
        }
    }

    public final AFi1aSDK AFAdRevenueData(Runnable runnable) {
        return new AFi1aSDK(new m(this, runnable, 0), this.getMediationNetwork.getMonetizationNetwork(), this.getMediationNetwork.getRevenue());
    }

    public final synchronized void getMediationNetwork(AFj1qSDK aFj1qSDK) {
        this.getCurrencyIso4217Code.add(aFj1qSDK);
    }

    @NonNull
    public final synchronized AFj1qSDK[] getRevenue() {
        return (AFj1qSDK[]) this.getCurrencyIso4217Code.toArray(new AFj1qSDK[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void getCurrencyIso4217Code(Runnable runnable) {
        AFj1dSDK.getMediationNetwork(this.getMediationNetwork.AFAdRevenueData(), new m(this, runnable, 1), 0L, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void getRevenue(Runnable runnable) {
        try {
            if (getCurrencyIso4217Code(new AFh1kSDK())) {
                runnable.run();
            }
        } catch (Throwable th) {
            AFLogger.afErrorLog(th.getMessage(), th);
        }
    }

    public final void getMediationNetwork(Runnable runnable) {
        getMediationNetwork(new AFj1zSDK(this.getMediationNetwork.getRevenue(), this.getMediationNetwork.getMonetizationNetwork(), AFj1ySDK.FACEBOOK, runnable, new m(this, runnable, 2)));
    }

    public final Runnable AFAdRevenueData(AFi1aSDK aFi1aSDK, Runnable runnable) {
        return new RunnableC0130g(this, aFi1aSDK, runnable, 23);
    }

    public final boolean getCurrencyIso4217Code(AFh1rSDK aFh1rSDK) {
        int iAFAdRevenueData = this.getMediationNetwork.getRevenue().getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0);
        return (!this.getMediationNetwork.component2().getMediationNetwork(AppsFlyerProperties.NEW_REFERRER_SENT, false) && iAFAdRevenueData == 1) || (iAFAdRevenueData == 1 && !(aFh1rSDK instanceof AFh1kSDK));
    }

    public final boolean AFAdRevenueData() {
        Iterator<AFj1qSDK> it2 = this.getCurrencyIso4217Code.iterator();
        while (it2.hasNext()) {
            if (it2.next().component4 == AFj1qSDK.AFa1ySDK.STARTED) {
                return false;
            }
        }
        return true;
    }

    public final boolean getMonetizationNetwork() {
        return this.getMediationNetwork.getRevenue().getMonetizationNetwork("AF_PREINSTALL_DISABLED", false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void getMonetizationNetwork(Runnable runnable) {
        AFj1zSDK aFj1zSDK = new AFj1zSDK(this.getMediationNetwork.getRevenue(), this.getMediationNetwork.getMonetizationNetwork(), AFj1ySDK.FACEBOOK_LITE, runnable, new RunnableC0131h(2));
        getMediationNetwork(aFj1zSDK);
        aFj1zSDK.getRevenue(this.getMediationNetwork.AFInAppEventType().getMonetizationNetwork);
    }
}
