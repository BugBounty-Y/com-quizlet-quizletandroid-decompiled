package com.amazon.device.ads;

import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
class OrientationProperty extends MraidProperty {
    boolean allowOrientationChange;
    boolean forceOrientation;

    public OrientationProperty(Map<String, String> map) {
        super("orientationProperty");
        this.allowOrientationChange = Boolean.parseBoolean(map.get("allowOrientationChange"));
        this.forceOrientation = Boolean.parseBoolean(map.get("forceOrientation"));
    }

    @Override // com.amazon.device.ads.MraidProperty
    public void formJSON(JSONObject jSONObject) throws JSONException {
    }
}
