package com.amazon.aps.shared.metrics.model;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final String b;
    public final JSONObject c;

    public a(JSONObject jSONObject, String name, String str) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = str;
        this.c = jSONObject;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        JSONObject jSONObject = this.c;
        return iHashCode2 + (jSONObject != null ? jSONObject.hashCode() : 0);
    }

    public final String toString() {
        return "ApsMetricsCustomEventInfo(name=" + this.a + ", value=" + ((Object) this.b) + ", extraAttrs=" + this.c + ')';
    }
}
