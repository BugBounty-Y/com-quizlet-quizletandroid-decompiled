package com.braze.support;

import com.braze.models.FeatureFlag;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class i {
    public static final i a = new i();

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to deserialize feature flag Json: ", jSONObject);
    }

    public final FeatureFlag a(JSONObject featureFlagObject) throws JSONException {
        Intrinsics.checkNotNullParameter(featureFlagObject, "featureFlagObject");
        try {
            String string = featureFlagObject.getString("id");
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            boolean z = featureFlagObject.getBoolean("enabled");
            JSONObject jSONObjectOptJSONObject = featureFlagObject.optJSONObject("properties");
            if (jSONObjectOptJSONObject == null) {
                jSONObjectOptJSONObject = new JSONObject();
            }
            return new FeatureFlag(string, z, jSONObjectOptJSONObject, JsonUtils.getOptionalString(featureFlagObject, "fts"));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.communication.dust.j(featureFlagObject, 13), 4, (Object) null);
            return null;
        }
    }
}
