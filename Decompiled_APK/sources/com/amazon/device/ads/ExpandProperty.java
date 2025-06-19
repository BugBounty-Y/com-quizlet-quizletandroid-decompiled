package com.amazon.device.ads;

import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
class ExpandProperty extends MraidProperty {
    int height;
    int width;

    public ExpandProperty(JSONObject jSONObject) throws JSONException {
        super("expandProperty");
        this.width = jSONObject.getInt(OTUXParamsKeys.OT_UX_WIDTH);
        this.height = jSONObject.getInt(OTUXParamsKeys.OT_UX_HEIGHT);
    }

    @Override // com.amazon.device.ads.MraidProperty
    public void formJSON(JSONObject jSONObject) throws JSONException {
    }
}
