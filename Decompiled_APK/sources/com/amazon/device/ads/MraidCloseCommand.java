package com.amazon.device.ads;

import org.json.JSONObject;

/* loaded from: classes.dex */
public class MraidCloseCommand extends MraidCommand {
    static final String NAME = "close";

    public static String getMraidName() {
        return NAME;
    }

    @Override // com.amazon.device.ads.MraidCommand
    public void execute(JSONObject jSONObject, DTBAdMRAIDController dTBAdMRAIDController) {
        dTBAdMRAIDController.onMRAIDClose();
    }

    @Override // com.amazon.device.ads.MraidCommand
    public String getName() {
        return NAME;
    }
}
