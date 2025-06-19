package com.appsflyer.internal;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.telephony.TelephonyManager;
import com.appsflyer.AFLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class AFi1pSDK {

    @NotNull
    public static final AFa1uSDK AFa1uSDK = new AFa1uSDK(null);
    ConnectivityManager getMonetizationNetwork;
    private final TelephonyManager getRevenue;

    @Metadata
    public static final class AFa1uSDK {
        private AFa1uSDK() {
        }

        public /* synthetic */ AFa1uSDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public AFi1pSDK(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "");
        Object systemService = context.getSystemService("connectivity");
        this.getMonetizationNetwork = systemService instanceof ConnectivityManager ? (ConnectivityManager) systemService : null;
        Object systemService2 = context.getSystemService("phone");
        this.getRevenue = systemService2 instanceof TelephonyManager ? (TelephonyManager) systemService2 : null;
    }

    public static boolean v_(NetworkInfo networkInfo) {
        if (networkInfo != null) {
            return networkInfo.isConnectedOrConnecting();
        }
        return false;
    }

    @NotNull
    public final AFi1rSDK getMediationNetwork() {
        Throwable th;
        String str;
        String simOperatorName;
        String networkOperatorName = null;
        try {
            TelephonyManager telephonyManager = this.getRevenue;
            if (telephonyManager != null) {
                simOperatorName = telephonyManager.getSimOperatorName();
                try {
                    networkOperatorName = telephonyManager.getNetworkOperatorName();
                    if (networkOperatorName == null || networkOperatorName.length() == 0) {
                        if (telephonyManager.getPhoneType() == 2) {
                            networkOperatorName = "CDMA";
                        }
                    }
                } catch (Throwable th2) {
                    str = networkOperatorName;
                    networkOperatorName = simOperatorName;
                    th = th2;
                    AFLogger.afErrorLog("Exception while collecting network info. ", th);
                    simOperatorName = networkOperatorName;
                    networkOperatorName = str;
                    return new AFi1rSDK(getRevenue(), networkOperatorName, simOperatorName, getMonetizationNetwork());
                }
            } else {
                simOperatorName = null;
            }
        } catch (Throwable th3) {
            th = th3;
            str = null;
        }
        return new AFi1rSDK(getRevenue(), networkOperatorName, simOperatorName, getMonetizationNetwork());
    }

    public abstract boolean getMonetizationNetwork();

    @NotNull
    public abstract String getRevenue();
}
