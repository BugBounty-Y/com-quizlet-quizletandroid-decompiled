package com.google.android.gms.internal.ads;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.jl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2235jl {
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final String e;
    public final int f;
    public final boolean g;

    public C2235jl(String str, String str2, String str3, int i, String str4, int i2, boolean z) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = i;
        this.e = str4;
        this.f = i2;
        this.g = z;
    }

    public final JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("adapterClassName", this.a);
        jSONObject.put("version", this.c);
        C2601s7 c2601s7 = AbstractC2773w7.q9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            jSONObject.put("sdkVersion", this.b);
        }
        jSONObject.put("status", this.d);
        jSONObject.put(OTUXParamsKeys.OT_UX_DESCRIPTION, this.e);
        jSONObject.put("initializationLatencyMillis", this.f);
        if (((Boolean) rVar.c.a(AbstractC2773w7.r9)).booleanValue()) {
            jSONObject.put("supportsInitialization", this.g);
        }
        return jSONObject;
    }
}
