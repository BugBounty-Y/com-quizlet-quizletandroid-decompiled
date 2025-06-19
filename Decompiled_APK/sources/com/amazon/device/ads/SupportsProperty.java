package com.amazon.device.ads;

import org.json.JSONException;

/* loaded from: classes.dex */
class SupportsProperty extends MraidDictionaryProperty {
    public SupportsProperty() throws JSONException {
        super("supports");
        try {
            this.data.put("tel", SDKUtilities.isTelSupported());
            this.data.put("sms", false);
            this.data.put("calendar", false);
            this.data.put("storePicture", false);
            this.data.put("inlineVideo", false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
