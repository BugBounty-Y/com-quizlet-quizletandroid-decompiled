package com.amazon.device.ads;

import java.io.UnsupportedEncodingException;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class MraidOpenCommand extends MraidCommand {
    static final String NAME = "open";

    public static String getMraidName() {
        return NAME;
    }

    @Override // com.amazon.device.ads.MraidCommand
    public void execute(JSONObject jSONObject, DTBAdMRAIDController dTBAdMRAIDController) throws JSONException, UnsupportedEncodingException {
        if (!jSONObject.has("options") || !jSONObject.getJSONObject("options").has("inAppNativeBrowser")) {
            dTBAdMRAIDController.openUrl(jSONObject.getString(DTBMetricsConfiguration.APSMETRICS_URL));
            return;
        }
        JSONObject jSONObject2 = jSONObject.getJSONObject("options").getJSONObject("inAppNativeBrowser");
        try {
            if (jSONObject2.has("enabled") && jSONObject2.getBoolean("enabled")) {
                dTBAdMRAIDController.openUrl(jSONObject.getString(DTBMetricsConfiguration.APSMETRICS_URL), jSONObject2.getBoolean("enabled"));
            }
        } catch (Exception e) {
            com.amazon.aps.shared.a.e(1, 1, "Failed to execute Open command with inAppNativeBrowser", e);
        }
    }

    @Override // com.amazon.device.ads.MraidCommand
    public String getName() {
        return NAME;
    }
}
