package com.braze.triggers.config;

import com.braze.support.BrazeLogger;
import com.braze.support.v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b implements a {
    public final int a;

    public b(JSONObject json) {
        Intrinsics.checkNotNullParameter(json, "json");
        this.a = json.optInt("re_eligibility", -1);
    }

    public static final String b() {
        return "Could not convert ReEligibilityConfig to JSON";
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() {
        try {
            return new JSONObject().put("re_eligibility", this.a);
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new v(28), 4, (Object) null);
            return null;
        }
    }
}
