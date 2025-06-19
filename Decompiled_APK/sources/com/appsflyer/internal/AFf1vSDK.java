package com.appsflyer.internal;

import android.util.Base64;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.net.MalformedURLException;
import java.net.URL;

/* loaded from: classes.dex */
public final class AFf1vSDK extends AFe1dSDK<String> {
    private final AFh1mSDK component2;

    public AFf1vSDK(@NonNull AFh1mSDK aFh1mSDK, @NonNull AFc1dSDK aFc1dSDK) {
        AFe1mSDK aFe1mSDK = aFh1mSDK.toString;
        AFe1mSDK aFe1mSDK2 = aFe1mSDK == null ? AFe1mSDK.CACHED_EVENT : aFe1mSDK;
        AFe1mSDK[] aFe1mSDKArr = {AFe1mSDK.RC_CDN};
        StringBuilder sb = new StringBuilder();
        sb.append(aFh1mSDK.getRevenue);
        sb.append("-");
        sb.append(getRevenue(aFh1mSDK));
        super(aFe1mSDK2, aFe1mSDKArr, aFc1dSDK, sb.toString(), aFh1mSDK.getRevenue);
        this.component2 = aFh1mSDK;
    }

    private boolean copy() {
        ResponseNetwork responseNetwork;
        AFe1mSDK aFe1mSDK = this.component2.toString;
        if (aFe1mSDK == null) {
            aFe1mSDK = AFe1mSDK.CACHED_EVENT;
        }
        return aFe1mSDK == AFe1mSDK.ARS_VALIDATE && (responseNetwork = ((AFe1dSDK) this).component1) != null && responseNetwork.getStatusCode() == 424;
    }

    private boolean equals() {
        ResponseNetwork responseNetwork = ((AFe1dSDK) this).component1;
        boolean z = this.getMediationNetwork == AFe1rSDK.FAILURE && responseNetwork != null && responseNetwork.getStatusCode() / com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR == 1;
        AFe1mSDK aFe1mSDK = this.getMonetizationNetwork;
        return z && (aFe1mSDK == AFe1mSDK.CONVERSION || aFe1mSDK == AFe1mSDK.ATTR);
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AppsFlyerRequestListener component3() {
        return this.component2.getCurrencyIso4217Code;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean copydefault() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return super.getMediationNetwork() || copy() || equals();
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AFd1nSDK<String> getRevenue(@NonNull String str) {
        String strEncodeToString = Base64.encodeToString(this.component2.AFAdRevenueData(), 2);
        AFLogger.afInfoLog("cached data: ".concat(String.valueOf(strEncodeToString)));
        ((AFe1dSDK) this).areAllFieldsValid.getCurrencyIso4217Code(this.component2.component1, strEncodeToString);
        AFd1oSDK aFd1oSDK = this.component4;
        return (AFd1nSDK) AFd1oSDK.getCurrencyIso4217Code(new Object[]{aFd1oSDK, this.component2}, -44698683, 44698684, System.identityHashCode(aFd1oSDK));
    }

    private static String getRevenue(AFh1mSDK aFh1mSDK) {
        try {
            return new URL(aFh1mSDK.component1).getHost();
        } catch (MalformedURLException unused) {
            return "";
        }
    }
}
