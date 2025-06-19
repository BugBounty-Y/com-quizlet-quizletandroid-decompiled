package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import com.appsflyer.AdRevenueScheme;
import com.pubmatic.sdk.openwrap.core.v;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class y {
    protected static final int BOXING_ALLOWED = 1;
    protected static final int PLAYBACK_END = 1;

    @NonNull
    private final a a;

    @NonNull
    private v.b b = v.b.UNKNOWN;

    @NonNull
    private final b c;

    @NonNull
    private final com.pubmatic.sdk.common.f d;
    private JSONArray e;
    protected static final int[] PROTOCOLS = {2, 3, 5, 6, 7, 8, 11, 12, 13, 14};
    protected static final String[] MIMES = com.pubmatic.sdk.video.player.q.getStringValues();
    protected static final int[] DELIVERY = {2};
    protected static final int[] COMPANION_TYPE = {1, 2, 3};

    public enum a {
        LINEAR(1),
        NON_LINEAR(2);

        private final int b;

        a(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    public enum b {
        IN_BANNER(2),
        INTERSTITIAL(5);

        private final int b;

        b(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    public y(@NonNull b bVar, @NonNull a aVar, @NonNull com.pubmatic.sdk.common.f fVar) {
        this.d = fVar;
        this.c = bVar;
        this.a = aVar;
    }

    @NonNull
    public com.pubmatic.sdk.common.f getAdSize() {
        return this.d;
    }

    public JSONArray getCompanionAds() {
        return this.e;
    }

    @NonNull
    public a getLinearity() {
        return this.a;
    }

    public v.b getPosition() {
        return this.b;
    }

    @NonNull
    public JSONObject getRTBJson() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("w", this.d.getAdWidth());
        jSONObject.put("h", this.d.getAdHeight());
        if (this.e == null) {
            c cVar = new c(this.d);
            cVar.setAdPosition(this.b);
            this.e = new JSONArray(new JSONObject[]{cVar.getRTBJson(new HashSet(), true)});
        }
        jSONObject.put("companionad", this.e);
        jSONObject.put("pos", this.b.getValue());
        jSONObject.put("protocols", new JSONArray(PROTOCOLS));
        jSONObject.put("mimes", new JSONArray(MIMES));
        jSONObject.put("linearity", this.a.getValue());
        jSONObject.put("boxingallowed", 1);
        jSONObject.put("delivery", new JSONArray(DELIVERY));
        jSONObject.put("companiontype", new JSONArray(COMPANION_TYPE));
        jSONObject.put(AdRevenueScheme.PLACEMENT, this.c.getValue());
        jSONObject.put("playbackend", 1);
        jSONObject.put("startdelay", 0);
        Set<Integer> supportedAPIs = getSupportedAPIs();
        if (!supportedAPIs.isEmpty()) {
            jSONObject.put("api", new JSONArray((Collection) supportedAPIs));
        }
        return jSONObject;
    }

    @NonNull
    public Set<Integer> getSupportedAPIs() {
        HashSet hashSet = new HashSet();
        if (com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBVideoMeasurement") != null) {
            hashSet.add(Integer.valueOf(v.a.OMSDK.getValue()));
        }
        return hashSet;
    }

    public void setCompanionAds(@NonNull JSONArray jSONArray) {
        this.e = jSONArray;
    }

    public void setPosition(@NonNull v.b bVar) {
        this.b = bVar;
    }
}
