package com.appsflyer.internal;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFi1rSDK {
    public final String AFAdRevenueData;

    @NotNull
    public final String getCurrencyIso4217Code;
    private final boolean getMonetizationNetwork;
    public final String getRevenue;

    public AFi1rSDK(@NotNull String str, String str2, String str3, boolean z) {
        Intrinsics.checkNotNullParameter(str, "");
        this.getCurrencyIso4217Code = str;
        this.getRevenue = str2;
        this.AFAdRevenueData = str3;
        this.getMonetizationNetwork = z;
    }

    public final boolean getMediationNetwork() {
        return this.getMonetizationNetwork;
    }
}
