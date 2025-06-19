package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFi1wSDK {

    @NonNull
    public final AFh1aSDK AFAdRevenueData;

    @NonNull
    public final String getCurrencyIso4217Code;
    private final boolean getMediationNetwork;
    public final AFh1cSDK getMonetizationNetwork;

    @NonNull
    public final String getRevenue;

    public AFi1wSDK(@NonNull String str) throws JSONException {
        if (str == null) {
            throw new JSONException("Failed to parse remote configuration JSON: originalJson is null");
        }
        try {
            JSONObject jSONObject = new JSONObject(str);
            String string = jSONObject.getString("ver");
            this.getRevenue = string;
            this.getMediationNetwork = jSONObject.optBoolean("test_mode");
            this.getCurrencyIso4217Code = str;
            this.AFAdRevenueData = string.startsWith("default") ? AFh1aSDK.DEFAULT : AFh1aSDK.CUSTOM;
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("features");
            this.getMonetizationNetwork = jSONObjectOptJSONObject != null ? new AFh1cSDK(jSONObjectOptJSONObject) : null;
        } catch (JSONException e) {
            AFLogger.afErrorLogForExcManagerOnly("Error in RC config parsing", e);
            throw new JSONException("Failed to parse remote configuration JSON");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || AFi1wSDK.class != obj.getClass()) {
            return false;
        }
        AFi1wSDK aFi1wSDK = (AFi1wSDK) obj;
        if (this.getMediationNetwork == aFi1wSDK.getMediationNetwork && this.getRevenue.equals(aFi1wSDK.getRevenue)) {
            return this.getCurrencyIso4217Code.equals(aFi1wSDK.getCurrencyIso4217Code);
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.getCurrencyIso4217Code.hashCode() + ((this.getRevenue.hashCode() + ((this.getMediationNetwork ? 1 : 0) * 31)) * 31);
        AFh1cSDK aFh1cSDK = this.getMonetizationNetwork;
        if (aFh1cSDK == null) {
            return iHashCode;
        }
        return aFh1cSDK.hashCode() + (iHashCode * 31);
    }
}
