package com.appsflyer.internal;

import android.net.Uri;
import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFe1lSDK.AnonymousClass5;

/* loaded from: classes.dex */
public final class AFe1bSDK extends AFe1sSDK<Boolean> {
    private static volatile boolean component3 = false;
    private final AFc1dSDK areAllFieldsValid;
    private Boolean component1;
    private final AFc1vSDK component2;
    private final AFe1lSDK component4;

    public AFe1bSDK(@NonNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.LOAD_CACHE, new AFe1mSDK[0], "LoadCachedRequests");
        this.component2 = aFc1dSDK.AFInAppEventParameterName();
        this.component4 = aFc1dSDK.copydefault();
        this.areAllFieldsValid = aFc1dSDK;
    }

    public static boolean component3() {
        return component3;
    }

    private static String getRevenue(AFc1rSDK aFc1rSDK) throws NumberFormatException {
        long jCurrentTimeMillis = System.currentTimeMillis();
        long j = Long.parseLong(aFc1rSDK.getMediationNetwork, 10);
        String str = aFc1rSDK.getRevenue;
        try {
            return Uri.parse(str).buildUpon().appendQueryParameter("isCachedRequest", "true").appendQueryParameter("timeincache", String.valueOf((jCurrentTimeMillis - j) / 1000)).toString();
        } catch (Exception e) {
            AFLogger.afErrorLogForExcManagerOnly("Couldn't parse the uri", e);
            return str;
        }
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    @NonNull
    public final AFe1rSDK getCurrencyIso4217Code() throws Exception {
        for (AFc1rSDK aFc1rSDK : this.component2.getRevenue()) {
            AFLogger aFLogger = AFLogger.INSTANCE;
            AFg1cSDK aFg1cSDK = AFg1cSDK.CACHE;
            StringBuilder sb = new StringBuilder("resending request: ");
            sb.append(aFc1rSDK.getRevenue);
            aFLogger.i(aFg1cSDK, sb.toString());
            try {
                AFh1mSDK aFh1mSDK = new AFh1mSDK(getRevenue(aFc1rSDK), aFc1rSDK.getMediationNetwork(), aFc1rSDK.getMediationNetwork, aFc1rSDK.getMonetizationNetwork);
                AFe1lSDK aFe1lSDK = this.component4;
                aFe1lSDK.getRevenue.execute(aFe1lSDK.new AnonymousClass5(new AFf1vSDK(aFh1mSDK, this.areAllFieldsValid)));
            } catch (Exception e) {
                AFLogger.INSTANCE.e(AFg1cSDK.QUEUE, "Failed to resend cached request", e);
            }
        }
        this.component1 = Boolean.TRUE;
        component3 = true;
        return AFe1rSDK.SUCCESS;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return 30000L;
    }
}
