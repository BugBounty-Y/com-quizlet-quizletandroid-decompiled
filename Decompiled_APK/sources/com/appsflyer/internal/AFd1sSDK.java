package com.appsflyer.internal;

import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFd1sSDK {
    public static boolean getMediationNetwork(@NotNull String str, @NotNull String str2) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(str2, "");
        int monetizationNetwork = AFj1aSDK.getMonetizationNetwork(str);
        int monetizationNetwork2 = AFj1aSDK.getMonetizationNetwork(str2);
        Pair<Integer, Integer> revenue = AFd1rSDK.getRevenue(str2);
        Pair<Integer, Integer> mediationNetwork = AFd1rSDK.getMediationNetwork(str2);
        return (monetizationNetwork2 == -1 || revenue != null) ? mediationNetwork != null ? ((Number) mediationNetwork.a).intValue() <= monetizationNetwork && monetizationNetwork <= ((Number) mediationNetwork.b).intValue() : revenue != null && ((Number) revenue.a).intValue() <= monetizationNetwork && monetizationNetwork <= ((Number) revenue.b).intValue() : monetizationNetwork2 == monetizationNetwork;
    }
}
