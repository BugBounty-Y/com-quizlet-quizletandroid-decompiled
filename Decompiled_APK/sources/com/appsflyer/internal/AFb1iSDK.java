package com.appsflyer.internal;

import java.security.SecureRandom;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFb1iSDK {

    @NotNull
    public static final AFb1iSDK INSTANCE = new AFb1iSDK();
    private static String getCurrencyIso4217Code;

    private AFb1iSDK() {
    }

    public static final synchronized void getCurrencyIso4217Code(@NotNull String str, @NotNull AFc1qSDK aFc1qSDK) {
        Intrinsics.checkNotNullParameter(str, "");
        Intrinsics.checkNotNullParameter(aFc1qSDK, "");
        getCurrencyIso4217Code = str;
        aFc1qSDK.getCurrencyIso4217Code("CUSTOM_INSTALL_ID_APPLIED", true);
        aFc1qSDK.getMediationNetwork("AF_INSTALLATION", str);
    }

    @NotNull
    public static final synchronized String getRevenue(@NotNull AFc1qSDK aFc1qSDK) {
        String str;
        try {
            Intrinsics.checkNotNullParameter(aFc1qSDK, "");
            if (getCurrencyIso4217Code == null) {
                String strAFAdRevenueData = aFc1qSDK.AFAdRevenueData("AF_INSTALLATION", (String) null);
                if (strAFAdRevenueData == null) {
                    strAFAdRevenueData = System.currentTimeMillis() + "-" + Math.abs(new SecureRandom().nextLong());
                    aFc1qSDK.getMediationNetwork("AF_INSTALLATION", strAFAdRevenueData);
                }
                getCurrencyIso4217Code = strAFAdRevenueData;
            }
            str = getCurrencyIso4217Code;
            Intrinsics.d(str);
        } catch (Throwable th) {
            throw th;
        }
        return str;
    }
}
