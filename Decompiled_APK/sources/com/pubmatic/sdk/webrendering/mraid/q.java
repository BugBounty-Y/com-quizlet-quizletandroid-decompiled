package com.pubmatic.sdk.webrendering.mraid;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class q implements n {
    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public String a() {
        return "resize";
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public boolean b() {
        return true;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public com.pubmatic.sdk.common.h a(JSONObject jSONObject, t tVar, boolean z) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("params");
        if (jSONObjectOptJSONObject == null) {
            return new com.pubmatic.sdk.common.h(1009, "Invalid MRAID command for orientation event");
        }
        tVar.resize(jSONObjectOptJSONObject.optInt(OTUXParamsKeys.OT_UX_WIDTH, 0), jSONObjectOptJSONObject.optInt(OTUXParamsKeys.OT_UX_HEIGHT, 0), jSONObjectOptJSONObject.optInt("offsetX", 0), jSONObjectOptJSONObject.optInt("offsetY", 0), jSONObjectOptJSONObject.optBoolean("allowOffscreen", false), z);
        return null;
    }
}
