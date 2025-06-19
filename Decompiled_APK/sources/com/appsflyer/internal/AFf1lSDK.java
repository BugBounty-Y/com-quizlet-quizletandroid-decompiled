package com.appsflyer.internal;

import android.util.Base64;
import com.appsflyer.AFLogger;
import java.nio.charset.Charset;

/* loaded from: classes.dex */
public final class AFf1lSDK {
    public AFi1wSDK AFAdRevenueData = null;
    public AFi1wSDK getCurrencyIso4217Code = getCurrencyIso4217Code();
    public long getMediationNetwork;
    public final AFc1qSDK getMonetizationNetwork;
    public long getRevenue;

    public AFf1lSDK(AFc1qSDK aFc1qSDK) {
        this.getMonetizationNetwork = aFc1qSDK;
        this.getMediationNetwork = aFc1qSDK.getCurrencyIso4217Code("af_rc_timestamp", 0L);
        this.getRevenue = aFc1qSDK.getCurrencyIso4217Code("af_rc_max_age", 0L);
    }

    private AFi1wSDK getCurrencyIso4217Code() {
        String strAFAdRevenueData = this.getMonetizationNetwork.AFAdRevenueData("af_remote_config", (String) null);
        if (strAFAdRevenueData == null) {
            AFLogger.INSTANCE.d(AFg1cSDK.REMOTE_CONTROL, "No configuration found in cache");
            return null;
        }
        try {
            return new AFi1wSDK(new String(Base64.decode(strAFAdRevenueData, 2), Charset.defaultCharset()));
        } catch (Exception e) {
            AFLogger.INSTANCE.e(AFg1cSDK.REMOTE_CONTROL, "Error reading malformed configuration from cache, requires fetching from remote again", e, true);
            return null;
        }
    }
}
