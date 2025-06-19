package com.braze.models.outgoing;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.braze.models.IPutIntoJson;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class k implements IPutIntoJson, com.braze.models.k {
    public final String a;
    public final Boolean b;
    public final Boolean c;
    public final i d;

    public k(String str, Boolean bool, Boolean bool2, i iVar) {
        this.a = str;
        this.b = bool;
        this.c = bool2;
        this.d = iVar;
    }

    public final boolean b() {
        return this.c != null;
    }

    @Override // com.braze.models.k
    public final boolean isEmpty() throws JSONException {
        i iVar;
        JSONObject jSONObjectForJsonPut = forJsonPut();
        if (jSONObjectForJsonPut.length() == 0) {
            return true;
        }
        if (this.b == null && this.c == null && (iVar = this.d) != null) {
            return !iVar.b;
        }
        if (jSONObjectForJsonPut.length() == 1) {
            return jSONObjectForJsonPut.has("user_id");
        }
        return false;
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        String str = this.a;
        if (str != null && str.length() != 0) {
            jSONObject.put("user_id", this.a);
        }
        Boolean bool = this.b;
        if (bool != null) {
            jSONObject.put("feed", bool.booleanValue());
        }
        Boolean bool2 = this.c;
        if (bool2 != null) {
            jSONObject.put("triggers", bool2.booleanValue());
        }
        i iVar = this.d;
        if (iVar != null) {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("config_time", iVar.a);
            jSONObject.put(DTBMetricsConfiguration.CONFIG_DIR, jSONObject2);
        }
        return jSONObject;
    }
}
