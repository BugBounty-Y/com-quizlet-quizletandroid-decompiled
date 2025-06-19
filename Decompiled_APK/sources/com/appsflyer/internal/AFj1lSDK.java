package com.appsflyer.internal;

import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface AFj1lSDK {

    @NotNull
    public static final AFa1tSDK AFa1tSDK = AFa1tSDK.getMonetizationNetwork;

    public static final class AFa1tSDK {
        static final /* synthetic */ AFa1tSDK getMonetizationNetwork = new AFa1tSDK();

        private AFa1tSDK() {
        }
    }

    @NotNull
    Map<String, Object> AFAdRevenueData();

    void getCurrencyIso4217Code();

    void getRevenue();
}
