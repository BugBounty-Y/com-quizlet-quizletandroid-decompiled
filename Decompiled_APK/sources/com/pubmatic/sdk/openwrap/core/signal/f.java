package com.pubmatic.sdk.openwrap.core.signal;

import com.appsflyer.AdRevenueScheme;
import com.pubmatic.sdk.openwrap.core.v;
import com.pubmatic.sdk.openwrap.core.y;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class f extends y {

    @NotNull
    private final y.b f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(@NotNull y.b placement, @NotNull y.a linearity, @NotNull com.pubmatic.sdk.common.f adSize) {
        super(placement, linearity, adSize);
        Intrinsics.checkNotNullParameter(placement, "placement");
        Intrinsics.checkNotNullParameter(linearity, "linearity");
        Intrinsics.checkNotNullParameter(adSize, "adSize");
        this.f = placement;
    }

    @NotNull
    public final y.b getPlacement() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.openwrap.core.y
    @NotNull
    public JSONObject getRTBJson() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (this.f == y.b.INTERSTITIAL) {
            jSONObject.put("w", getAdSize().getAdWidth());
            jSONObject.put("h", getAdSize().getAdHeight());
        }
        if (getCompanionAds() == null) {
            com.pubmatic.sdk.openwrap.core.c cVar = new com.pubmatic.sdk.openwrap.core.c(getAdSize());
            cVar.setAdPosition(getPosition());
            setCompanionAds(new JSONArray(new JSONObject[]{cVar.getRTBJson(new HashSet(), true)}));
        }
        jSONObject.put("companionad", getCompanionAds());
        v.b position = getPosition();
        if (position != null) {
            jSONObject.put("pos", position.getValue());
        }
        jSONObject.put("protocols", new JSONArray(y.PROTOCOLS));
        jSONObject.put("mimes", new JSONArray(y.MIMES));
        jSONObject.put("linearity", getLinearity().getValue());
        jSONObject.put("boxingallowed", 1);
        jSONObject.put("delivery", new JSONArray(y.DELIVERY));
        jSONObject.put("companiontype", new JSONArray(y.COMPANION_TYPE));
        jSONObject.put(AdRevenueScheme.PLACEMENT, this.f.getValue());
        jSONObject.put("playbackend", 1);
        jSONObject.put("startdelay", 0);
        Set<Integer> supportedAPIs = getSupportedAPIs();
        Intrinsics.checkNotNullExpressionValue(supportedAPIs, "getSupportedAPIs()");
        if (!supportedAPIs.isEmpty()) {
            jSONObject.put("api", new JSONArray((Collection) supportedAPIs));
        }
        return jSONObject;
    }
}
