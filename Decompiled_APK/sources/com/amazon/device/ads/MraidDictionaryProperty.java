package com.amazon.device.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
class MraidDictionaryProperty extends MraidProperty {
    JSONObject data;

    public MraidDictionaryProperty(String str) {
        super(str);
        this.data = new JSONObject();
    }

    @Override // com.amazon.device.ads.MraidProperty
    public void formJSON(JSONObject jSONObject) throws JSONException {
        jSONObject.put(this.name, this.data);
    }

    public JSONObject getData() {
        return this.data;
    }
}
