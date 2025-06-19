package com.braze.communication;

import java.util.Map;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class d {
    public final int a;
    public final Map b;
    public final JSONObject c;

    public d(int i, Map responseHeaders, JSONObject jSONObject) {
        Intrinsics.checkNotNullParameter(responseHeaders, "responseHeaders");
        this.a = i;
        this.b = responseHeaders;
        this.c = jSONObject;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c);
    }

    public final int hashCode() {
        int iD = assistantMode.refactored.a.d(Integer.hashCode(this.a) * 31, 31, this.b);
        JSONObject jSONObject = this.c;
        return iD + (jSONObject == null ? 0 : jSONObject.hashCode());
    }

    public final String toString() {
        return "HttpConnectorResult(responseCode=" + this.a + ", responseHeaders=" + this.b + ", jsonResponse=" + this.c + ')';
    }

    public /* synthetic */ d(int i, Map map, int i2) {
        this(i, (i2 & 2) != 0 ? V.c() : map, (JSONObject) null);
    }
}
