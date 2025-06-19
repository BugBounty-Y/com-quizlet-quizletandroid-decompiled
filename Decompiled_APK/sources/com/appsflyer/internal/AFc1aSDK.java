package com.appsflyer.internal;

import java.util.List;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public interface AFc1aSDK {
    String AFAdRevenueData(@NotNull Throwable th, @NotNull String str);

    void AFAdRevenueData(int i, int i2);

    int getCurrencyIso4217Code();

    @NotNull
    List<AFc1cSDK> getMediationNetwork();

    boolean getMonetizationNetwork();

    boolean getRevenue(@NotNull String... strArr);
}
