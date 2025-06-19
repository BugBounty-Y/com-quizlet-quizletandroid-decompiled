package com.pubmatic.sdk.webrendering.mraid;

import org.json.JSONObject;

/* loaded from: classes2.dex */
public class D implements n {
    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public String a() {
        return "unload";
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public boolean b() {
        return false;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.n
    public com.pubmatic.sdk.common.h a(JSONObject jSONObject, t tVar, boolean z) {
        tVar.unload();
        return null;
    }
}
