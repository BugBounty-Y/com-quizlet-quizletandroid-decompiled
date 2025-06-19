package com.google.android.gms.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class l extends b {
    public final q e;

    public l(int i, String str, String str2, b bVar, q qVar) {
        super(i, str, str2, bVar);
        this.e = qVar;
    }

    @Override // com.google.android.gms.ads.b
    public final JSONObject b() throws JSONException {
        JSONObject jSONObjectB = super.b();
        q qVar = this.e;
        if (qVar == null) {
            jSONObjectB.put("Response Info", "null");
            return jSONObjectB;
        }
        jSONObjectB.put("Response Info", qVar.a());
        return jSONObjectB;
    }

    @Override // com.google.android.gms.ads.b
    public final String toString() {
        try {
            return b().toString(2);
        } catch (JSONException unused) {
            return "Error forming toString output.";
        }
    }
}
