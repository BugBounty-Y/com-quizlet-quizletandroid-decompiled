package com.google.android.gms.ads;

import com.google.android.gms.ads.internal.client.zze;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b {
    public final int a;
    public final String b;
    public final String c;
    public final b d;

    public b(int i, String str, String str2, b bVar) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = bVar;
    }

    public final zze a() {
        b bVar = this.d;
        return new zze(this.a, this.b, this.c, bVar == null ? null : new zze(bVar.a, bVar.b, bVar.c, null, null), null);
    }

    public JSONObject b() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("Code", this.a);
        jSONObject.put("Message", this.b);
        jSONObject.put("Domain", this.c);
        b bVar = this.d;
        if (bVar == null) {
            jSONObject.put("Cause", "null");
            return jSONObject;
        }
        jSONObject.put("Cause", bVar.b());
        return jSONObject;
    }

    public String toString() {
        try {
            return b().toString(2);
        } catch (JSONException unused) {
            return "Error forming toString output.";
        }
    }
}
