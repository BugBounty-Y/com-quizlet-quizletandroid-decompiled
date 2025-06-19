package com.pubmatic.sdk.webrendering.ui;

import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdLoader;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.log.POBLog;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b {
    private final int a;
    private final boolean b;

    public static class a {
        private boolean a = false;
        private int b = 5;

        @NonNull
        public static b createBannerConfig(JSONObject jSONObject, @NonNull String str) {
            a aVar = new a();
            if (jSONObject != null) {
                JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("ext");
                if (jSONObjectOptJSONObject == null || jSONObjectOptJSONObject.length() <= 0) {
                    POBLog.warn("ConfigBuilder", "Null/empty extension response parameter.", new Object[0]);
                } else {
                    JSONObject jSONObjectOptJSONObject2 = jSONObjectOptJSONObject.optJSONObject(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER);
                    if (jSONObjectOptJSONObject2 == null || jSONObjectOptJSONObject2.length() <= 0) {
                        POBLog.warn("ConfigBuilder", "Null/empty banner response parameter.", new Object[0]);
                    } else {
                        POBLog.info("ConfigBuilder", assistantMode.refactored.a.j("Banner config: ", jSONObjectOptJSONObject2), new Object[0]);
                        JSONObject jSONObjectOptJSONObject3 = jSONObjectOptJSONObject2.optJSONObject("clientconfig");
                        if (jSONObjectOptJSONObject3 != null) {
                            aVar.setSkipAfter(jSONObjectOptJSONObject3.optInt(DTBAdLoader.APS_VIDEO_SKIP_AFTER, 5));
                            if (DTBAdSize.AAX_INTERSTITIAL_AD_SIZE.equals(str)) {
                                aVar.setBackButtonEnabled(jSONObjectOptJSONObject3.optBoolean("enablehardwarebackbutton", false));
                            }
                        }
                    }
                }
            }
            return aVar.build();
        }

        public b build() {
            return new b(this);
        }

        public a setBackButtonEnabled(boolean z) {
            this.a = z;
            return this;
        }

        public a setSkipAfter(int i) {
            this.b = i;
            return this;
        }
    }

    public int getSkipAfter() {
        return this.a;
    }

    public boolean isBackButtonEnabled() {
        return this.b;
    }

    private b(@NonNull a aVar) {
        this.a = aVar.b;
        this.b = aVar.a;
    }
}
