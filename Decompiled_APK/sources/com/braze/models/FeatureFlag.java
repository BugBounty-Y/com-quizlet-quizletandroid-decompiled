package com.braze.models;

import com.braze.managers.P;
import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class FeatureFlag implements IPutIntoJson<JSONObject> {
    public static final h Companion = new h();
    private final boolean enabled;
    private final String id;
    private final JSONObject properties;
    private final String trackingString;

    public FeatureFlag(String id, boolean z, JSONObject properties, String str) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(properties, "properties");
        this.id = id;
        this.enabled = z;
        this.properties = properties;
        this.trackingString = str;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String forJsonPut$lambda$0() {
        return "Caught exception creating FeatureFlag Json.";
    }

    public final FeatureFlag deepcopy$android_sdk_base_release() {
        return new FeatureFlag(this.id, this.enabled, JsonUtils.deepcopy(this.properties), this.trackingString);
    }

    public final String getId() {
        return this.id;
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("id", this.id);
            jSONObject.put("enabled", this.enabled);
            jSONObject.put("properties", this.properties);
            jSONObject.put("fts", this.trackingString);
            return jSONObject;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(28), 4, (Object) null);
            return jSONObject;
        }
    }
}
