package com.google.android.gms.internal.ads;

import android.util.JsonReader;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Yp {
    public final String a;
    public final String b;
    public final JSONObject c;
    public final JSONObject d;

    public Yp(JsonReader jsonReader) {
        JSONObject jSONObjectG = com.google.android.gms.internal.mlkit_vision_common.V2.g(jsonReader);
        this.d = jSONObjectG;
        this.a = jSONObjectG.optString("ad_html", null);
        this.b = jSONObjectG.optString("ad_base_url", null);
        this.c = jSONObjectG.optJSONObject("ad_json");
    }
}
