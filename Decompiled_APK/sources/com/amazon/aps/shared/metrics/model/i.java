package com.amazon.aps.shared.metrics.model;

import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public abstract class i {
    public final m a;
    public long b;
    public long c;

    public i(m mVar, long j, int i) {
        mVar = (i & 1) != 0 ? null : mVar;
        j = (i & 2) != 0 ? 0L : j;
        this.a = mVar;
        this.b = j;
        this.c = 0L;
    }

    public m a() {
        return this.a;
    }

    public JSONObject b() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        m mVarA = a();
        if (mVarA != null) {
            jSONObject.put("r", mVarA == m.a);
        }
        long j = this.b;
        if (j != 0) {
            jSONObject.put("st", j);
        }
        long j2 = this.c;
        if (j2 != 0) {
            jSONObject.put("et", j2);
        }
        return jSONObject;
    }
}
