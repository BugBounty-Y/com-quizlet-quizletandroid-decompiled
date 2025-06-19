package com.appsflyer.internal;

import com.appsflyer.deeplink.DeepLink;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFa1rSDK implements AFe1ySDK<AFa1mSDK> {
    @Override // com.appsflyer.internal.AFe1ySDK
    public final /* synthetic */ AFa1mSDK getMonetizationNetwork(String str) throws JSONException {
        JSONObject jSONObjectOptJSONObject;
        DeepLink revenue = null;
        if (str == null || str.length() == 0) {
            return new AFa1mSDK(false, null, 3, null);
        }
        JSONObject jSONObject = new JSONObject(str);
        boolean zOptBoolean = jSONObject.optBoolean("found", false);
        boolean zOptBoolean2 = jSONObject.optBoolean("is_second_ping", true);
        if (zOptBoolean && (jSONObjectOptJSONObject = jSONObject.optJSONObject("click_event")) != null) {
            revenue = DeepLink.getRevenue(jSONObjectOptJSONObject);
            revenue.getCurrencyIso4217Code.put("is_deferred", true);
        }
        return new AFa1mSDK(zOptBoolean2, revenue);
    }
}
