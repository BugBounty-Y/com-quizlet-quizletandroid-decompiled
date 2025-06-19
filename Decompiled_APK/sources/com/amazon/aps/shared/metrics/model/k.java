package com.amazon.aps.shared.metrics.model;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class k extends e {
    public String b;
    public String c;
    public Boolean d;
    public String e;
    public String f;
    public f g;
    public h h;
    public j i;
    public g j;
    public l k;

    @Override // com.amazon.aps.shared.metrics.model.e
    public final String a() {
        return "p";
    }

    @Override // com.amazon.aps.shared.metrics.model.e
    public final boolean b() {
        return this.g != null;
    }

    @Override // com.amazon.aps.shared.metrics.model.e
    public final JSONObject c() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("t", this.a);
        String str = this.b;
        if (str != null) {
            jSONObject.put("nw", str);
        }
        String str2 = this.c;
        if (str2 != null) {
            jSONObject.put("bi", str2);
        }
        String str3 = this.f;
        if (str3 != null) {
            jSONObject.put("ci", str3);
        }
        Boolean bool = this.d;
        if (bool != null) {
            jSONObject.put("vf", bool.booleanValue());
        }
        String str4 = this.e;
        if (str4 != null) {
            jSONObject.put("af", str4);
        }
        f fVar = this.g;
        if (fVar != null) {
            jSONObject.put("be", fVar.b());
        }
        h hVar = this.h;
        if (hVar != null) {
            jSONObject.put("fe", hVar.b());
        }
        j jVar = this.i;
        if (jVar != null) {
            jSONObject.put("ie", jVar.b());
        }
        g gVar = this.j;
        if (gVar != null) {
            jSONObject.put("ce", gVar.b());
        }
        l lVar = this.k;
        if (lVar == null) {
            return jSONObject;
        }
        jSONObject.put("vce", lVar.b());
        return jSONObject;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.b, ((k) obj).b);
    }

    public final int hashCode() {
        String str = this.b;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return "ApsMetricsPerfModel(networkName=" + ((Object) this.b) + ')';
    }
}
