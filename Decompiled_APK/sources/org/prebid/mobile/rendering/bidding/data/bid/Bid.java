package org.prebid.mobile.rendering.bidding.data.bid;

import org.json.JSONArray;
import org.json.JSONObject;
import org.prebid.mobile.rendering.interstitial.rewarded.RewardedClosingRules;
import org.prebid.mobile.rendering.interstitial.rewarded.RewardedCompletionRules;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.MobileSdkPassThrough;

/* loaded from: classes3.dex */
public class Bid {
    public double a;
    public String b;
    public Prebid c;
    public String d;
    public String e;
    public MobileSdkPassThrough f;

    public Bid() {
        new RewardedCompletionRules();
        new RewardedClosingRules();
    }

    public static void a(String str, JSONObject jSONObject) {
        JSONArray jSONArrayOptJSONArray;
        if (!jSONObject.has(str) || (jSONArrayOptJSONArray = jSONObject.optJSONArray(str)) == null || jSONArrayOptJSONArray.length() <= 0) {
            return;
        }
        int length = jSONArrayOptJSONArray.length();
        String[] strArr = new String[length];
        for (int i = 0; i < length; i++) {
            strArr[i] = jSONArrayOptJSONArray.optString(i);
        }
    }
}
