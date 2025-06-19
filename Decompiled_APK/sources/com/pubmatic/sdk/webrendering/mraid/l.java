package com.pubmatic.sdk.webrendering.mraid;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public class l implements n {
    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public String a() {
        return "createCalendarEvent";
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public boolean b() {
        return true;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public com.pubmatic.sdk.common.h a(JSONObject jSONObject, t tVar, boolean z) {
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("params");
        if (jSONObjectOptJSONObject == null) {
            return new com.pubmatic.sdk.common.h(1009, "Invalid MRAID command for createcalendarevent");
        }
        tVar.createCalendarEvent(jSONObjectOptJSONObject, z);
        return null;
    }
}
