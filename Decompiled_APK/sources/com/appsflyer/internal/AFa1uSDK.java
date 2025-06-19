package com.appsflyer.internal;

import com.appsflyer.internal.AFe1lSDK.AnonymousClass5;
import com.appsflyer.internal.AFe1tSDK;
import com.appsflyer.internal.AFe1uSDK;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFa1uSDK implements Runnable {
    private final Map<String, Object> getMediationNetwork;

    @NotNull
    private final AFc1dSDK getMonetizationNetwork;

    @NotNull
    private final AFh1rSDK getRevenue;

    public AFa1uSDK(@NotNull AFc1dSDK aFc1dSDK, @NotNull AFh1rSDK aFh1rSDK, Map<String, ? extends Object> map) {
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        this.getMonetizationNetwork = aFc1dSDK;
        this.getRevenue = aFh1rSDK;
        this.getMediationNetwork = map;
    }

    @Override // java.lang.Runnable
    public final void run() {
        AFf1rSDK aFf1sSDK;
        if (this.getRevenue.getMediationNetwork()) {
            AFf1uSDK aFf1uSDK = new AFf1uSDK(this.getRevenue, this.getMonetizationNetwork);
            aFf1uSDK.copydefault = this.getMediationNetwork;
            aFf1sSDK = aFf1uSDK;
        } else {
            aFf1sSDK = this.getRevenue instanceof AFh1lSDK ? new AFf1sSDK((AFh1lSDK) this.getRevenue, this.getMonetizationNetwork) : new AFf1rSDK(this.getRevenue, this.getMonetizationNetwork);
        }
        AFe1lSDK aFe1lSDKCopydefault = this.getMonetizationNetwork.copydefault();
        aFe1lSDKCopydefault.getRevenue.execute(aFe1lSDKCopydefault.new AnonymousClass5(aFf1sSDK));
        this.getMonetizationNetwork.AFKeystoreWrapper();
        if (AFe1zSDK.AFAdRevenueData()) {
            AFe1uSDK mediationNetwork = this.getMonetizationNetwork.getMediationNetwork();
            AFh1rSDK aFh1rSDK = this.getRevenue;
            Intrinsics.checkNotNullParameter(aFh1rSDK, "");
            if (AFj1iSDK.getRevenue(mediationNetwork.getRevenue.getMonetizationNetwork)) {
                AFe1tSDK.AFa1zSDK aFa1zSDK = AFe1tSDK.AFa1zSDK;
                AFe1tSDK revenue = AFe1tSDK.AFa1zSDK.getRevenue(aFh1rSDK);
                if (revenue == null) {
                    return;
                }
                mediationNetwork.getMediationNetwork(revenue, AFe1uSDK.AnonymousClass3.getRevenue);
            }
        }
    }
}
