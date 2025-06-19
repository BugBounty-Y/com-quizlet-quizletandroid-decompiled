package com.braze.models;

import com.braze.managers.P;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public static final String b() {
        return "Received null inner banner object. Not parsing.";
    }

    public final Banner a(JSONObject jSONObject) throws JSONException {
        if (jSONObject == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new P(29), 6, (Object) null);
            return null;
        }
        try {
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER);
            if (jSONObjectOptJSONObject == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new j(0), 6, (Object) null);
                return null;
            }
            String string = jSONObjectOptJSONObject.getString("id");
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            String string2 = jSONObjectOptJSONObject.getString("placement_id");
            Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
            String string3 = jSONObjectOptJSONObject.getString("html");
            Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
            return new Banner(string, string2, string3, jSONObjectOptJSONObject.getBoolean("is_control"), jSONObjectOptJSONObject.getLong("expires_at"), jSONObjectOptJSONObject.getBoolean("is_test_send"));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.communication.dust.j(jSONObject, 3), 4, (Object) null);
            return null;
        }
    }

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to deserialize banner Json: ", jSONObject);
    }

    public static final String a() {
        return "Received null banner object. Not parsing.";
    }
}
