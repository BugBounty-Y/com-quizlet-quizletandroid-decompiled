package org.prebid.mobile.rendering.bidding.events;

import org.json.JSONObject;

/* loaded from: classes3.dex */
public abstract class EventsNotifier {
    public static String a(String str, JSONObject jSONObject) {
        JSONObject jSONObjectOptJSONObject;
        JSONObject jSONObjectOptJSONObject2;
        JSONObject jSONObjectOptJSONObject3;
        if (jSONObject == null || (jSONObjectOptJSONObject = jSONObject.optJSONObject("ext")) == null || (jSONObjectOptJSONObject2 = jSONObjectOptJSONObject.optJSONObject("prebid")) == null || (jSONObjectOptJSONObject3 = jSONObjectOptJSONObject2.optJSONObject("events")) == null) {
            return null;
        }
        String strOptString = jSONObjectOptJSONObject3.optString(str, "");
        if (strOptString.isEmpty()) {
            return null;
        }
        return strOptString;
    }
}
