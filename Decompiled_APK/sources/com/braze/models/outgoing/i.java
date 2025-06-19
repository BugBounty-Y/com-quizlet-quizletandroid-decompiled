package com.braze.models.outgoing;

import com.braze.models.IPutIntoJson;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class i implements IPutIntoJson, com.braze.models.k {
    public final long a;
    public final boolean b;

    public i(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("config_time", this.a);
        return jSONObject;
    }

    @Override // com.braze.models.k
    public final boolean isEmpty() {
        return !this.b;
    }
}
