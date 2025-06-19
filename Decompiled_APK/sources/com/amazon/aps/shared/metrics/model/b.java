package com.amazon.aps.shared.metrics.model;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b extends e {
    public final a b;

    public b(a event) {
        Intrinsics.checkNotNullParameter(event, "event");
        this.b = event;
    }

    @Override // com.amazon.aps.shared.metrics.model.e
    public final String a() {
        return "c";
    }

    @Override // com.amazon.aps.shared.metrics.model.e
    public final boolean b() {
        return true;
    }

    @Override // com.amazon.aps.shared.metrics.model.e
    public final JSONObject c() throws JSONException {
        a aVar = this.b;
        aVar.getClass();
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("n", aVar.a);
        jSONObject.put("t", System.currentTimeMillis());
        String str = aVar.b;
        if (str != null) {
            jSONObject.put("vl", str);
        }
        JSONObject jSONObject2 = aVar.c;
        if (jSONObject2 == null) {
            return jSONObject;
        }
        jSONObject.put("ext", jSONObject2);
        return jSONObject;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.b, ((b) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "ApsMetricsCustomModel(event=" + this.b + ')';
    }
}
