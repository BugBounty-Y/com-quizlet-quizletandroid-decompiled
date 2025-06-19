package com.onetrust.otpublishers.headless.Public.DataModel;

import android.support.v4.media.session.a;
import androidx.annotation.NonNull;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class OTUXParams {
    public final JSONObject a;
    public final String b;

    public static class OTUXParamsBuilder {
        public String a;
        public JSONObject b;

        @NonNull
        public static OTUXParamsBuilder newInstance() {
            return new OTUXParamsBuilder();
        }

        @NonNull
        public OTUXParams build() {
            return new OTUXParams(this);
        }

        @NonNull
        public OTUXParamsBuilder setOTSDKTheme(String str) {
            this.a = str;
            return this;
        }

        @NonNull
        public OTUXParamsBuilder setUXParams(@NonNull JSONObject jSONObject) {
            this.b = jSONObject;
            return this;
        }
    }

    public OTUXParams(@NonNull OTUXParamsBuilder oTUXParamsBuilder) {
        this.a = oTUXParamsBuilder.b;
        this.b = oTUXParamsBuilder.a;
    }

    public String getOTSDKTheme() {
        return this.b;
    }

    public JSONObject getUxParam() {
        return this.a;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("OTUXParams{uxParam=");
        sb.append(this.a);
        sb.append(", otSDKTheme='");
        return a.t(sb, this.b, "'}");
    }
}
