package com.appsflyer.internal;

import android.content.Context;
import android.content.Intent;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerLib;
import com.appsflyer.AppsFlyerProperties;
import com.appsflyer.FirebaseMessagingServiceListener;
import com.google.firebase.messaging.FirebaseMessagingService;

/* loaded from: classes.dex */
public final class AFg1ySDK {
    public final AFc1qSDK AFAdRevenueData;

    public AFg1ySDK(@NonNull Context context) {
        this.AFAdRevenueData = ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getRevenue(context);
    }

    public static boolean getMonetizationNetwork(Context context) {
        if (AppsFlyerLib.getInstance().isStopped()) {
            return false;
        }
        try {
            String str = FirebaseMessagingService.ACTION_DIRECT_BOOT_REMOTE_INTENT;
            return AFj1iSDK.L_(context, new Intent("com.google.firebase.MESSAGING_EVENT", null, context, FirebaseMessagingServiceListener.class));
        } catch (ClassNotFoundException unused) {
            return false;
        } catch (Throwable th) {
            AFLogger.INSTANCE.e(AFg1cSDK.UNINSTALL, "An error occurred while trying to verify manifest declarations: ", th);
            return false;
        }
    }

    public final AFf1aSDK getRevenue() {
        String string;
        String string2;
        String strAFAdRevenueData = this.AFAdRevenueData.AFAdRevenueData("afUninstallToken", (String) null);
        long currencyIso4217Code = this.AFAdRevenueData.getCurrencyIso4217Code("afUninstallToken_received_time", 0L);
        boolean mediationNetwork = this.AFAdRevenueData.getMediationNetwork("afUninstallToken_queued", false);
        this.AFAdRevenueData.getCurrencyIso4217Code("afUninstallToken_queued", false);
        if (strAFAdRevenueData == null && (string2 = AppsFlyerProperties.getInstance().getString("afUninstallToken")) != null) {
            strAFAdRevenueData = string2.split(",")[r0.length - 1];
        }
        if (currencyIso4217Code == 0 && (string = AppsFlyerProperties.getInstance().getString("afUninstallToken")) != null) {
            String[] strArrSplit = string.split(",");
            if (strArrSplit.length >= 2) {
                try {
                    currencyIso4217Code = Long.parseLong(strArrSplit[strArrSplit.length - 2]);
                } catch (NumberFormatException unused) {
                }
            }
        }
        if (strAFAdRevenueData != null) {
            return new AFf1aSDK(strAFAdRevenueData, currencyIso4217Code, mediationNetwork);
        }
        return null;
    }

    public static boolean getMonetizationNetwork(@NonNull AFc1qSDK aFc1qSDK) {
        return aFc1qSDK.getMediationNetwork("sentRegisterRequestToAF", false);
    }
}
