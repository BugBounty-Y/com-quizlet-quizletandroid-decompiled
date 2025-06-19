package com.braze.models;

import com.braze.managers.P;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class Banner implements IPutIntoJson<JSONObject> {
    public static final a Companion = new a();
    private final long expirationTimestampSeconds;
    private final String html;
    private final boolean isControl;
    private final boolean isTestSend;
    private final String placementId;
    private final String trackingId;

    public Banner(String trackingId, String placementId, String html, boolean z, long j, boolean z2) {
        Intrinsics.checkNotNullParameter(trackingId, "trackingId");
        Intrinsics.checkNotNullParameter(placementId, "placementId");
        Intrinsics.checkNotNullParameter(html, "html");
        this.trackingId = trackingId;
        this.placementId = placementId;
        this.html = html;
        this.isControl = z;
        this.expirationTimestampSeconds = j;
        this.isTestSend = z2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String forJsonPut$lambda$0() {
        return "Caught exception creating Banner Json.";
    }

    public final Banner deepcopy$android_sdk_base_release() {
        return new Banner(this.trackingId, this.placementId, this.html, this.isControl, this.expirationTimestampSeconds, this.isTestSend);
    }

    public final String getPlacementId() {
        return this.placementId;
    }

    public final String getTrackingId() {
        return this.trackingId;
    }

    public final boolean isExpired() {
        long j = this.expirationTimestampSeconds;
        return j != -1 && j < DateTimeUtils.nowInSeconds();
    }

    public final boolean isTestSend() {
        return this.isTestSend;
    }

    public String toString() {
        return x.c("\n            Banner{\n            trackingId='" + this.trackingId + "'\n            placementId='" + this.placementId + "'\n            html='" + this.html + "'\n            isControl=" + this.isControl + "\n            expirationTimestampSeconds=" + this.expirationTimestampSeconds + "\n            isTestSend=" + this.isTestSend + "\n            }\n        ");
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        try {
            jSONObject2.put("id", this.trackingId);
            jSONObject2.put("placement_id", this.placementId);
            jSONObject2.put("html", this.html);
            jSONObject2.put("is_control", this.isControl);
            jSONObject2.put("expires_at", this.expirationTimestampSeconds);
            jSONObject2.put("is_test_send", this.isTestSend);
            jSONObject.put(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER, jSONObject2);
            return jSONObject;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(27), 4, (Object) null);
            return jSONObject;
        }
    }
}
