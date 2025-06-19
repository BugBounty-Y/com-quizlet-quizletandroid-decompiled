package com.pubmatic.sdk.openwrap.core.signal;

import com.pubmatic.sdk.openwrap.core.p;
import com.pubmatic.sdk.openwrap.core.v;
import com.pubmatic.sdk.openwrap.core.y;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a extends p {
    public a(boolean z, boolean z2) {
        super("NA", "NA", z, z2);
    }

    @Override // com.pubmatic.sdk.openwrap.core.p
    @NotNull
    public JSONObject getImpressionJson() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (com.pubmatic.sdk.common.i.getSdkConfig().isUseInternalBrowser()) {
            jSONObject.put("clickbrowser", 0);
        } else {
            jSONObject.put("clickbrowser", 1);
        }
        jSONObject.put("displaymanager", "PubMatic_OpenWrap_SDK");
        jSONObject.put("displaymanagerver", "3.7.0");
        JSONObject extJson = getExtJson(null);
        if (extJson != null && extJson.length() > 0) {
            jSONObject.putOpt("ext", extJson);
        }
        com.pubmatic.sdk.openwrap.core.c banner = getBanner();
        if (banner != null) {
            v.b bVar = this.adPosition;
            if (bVar != v.b.UNKNOWN) {
                banner.setAdPosition(bVar);
            }
            jSONObject.put(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER, banner.getRTBJson(banner.getSupportedAPIs(), false));
        }
        y video = getVideo();
        if (video == null) {
            return jSONObject;
        }
        v.b bVar2 = this.adPosition;
        if (bVar2 != v.b.UNKNOWN) {
            video.setPosition(bVar2);
        }
        jSONObject.put(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO, video.getRTBJson());
        return jSONObject;
    }
}
