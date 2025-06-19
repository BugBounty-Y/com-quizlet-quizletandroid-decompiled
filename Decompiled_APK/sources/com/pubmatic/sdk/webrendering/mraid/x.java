package com.pubmatic.sdk.webrendering.mraid;

import com.amazon.device.ads.DTBMetricsConfiguration;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class x implements n {
    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public String a() {
        return "playVideo";
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public boolean b() {
        return true;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public com.pubmatic.sdk.common.h a(JSONObject jSONObject, t tVar, boolean z) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("params");
        if (jSONObjectOptJSONObject == null) {
            return new com.pubmatic.sdk.common.h(1009, "Invalid MRAID command for playVideo event");
        }
        String strOptString = jSONObjectOptJSONObject.optString(DTBMetricsConfiguration.APSMETRICS_URL, null);
        if (strOptString == null) {
            return new com.pubmatic.sdk.common.h(1009, "Invalid MRAID Url for playVideo event");
        }
        tVar.playVideo(strOptString, z);
        return null;
    }
}
