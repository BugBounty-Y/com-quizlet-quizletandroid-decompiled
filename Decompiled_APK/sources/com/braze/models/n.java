package com.braze.models;

import com.braze.support.BrazeLogger;
import com.braze.support.JsonUtils;
import java.util.UUID;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class n implements IPutIntoJson {
    public final o a;
    public final double b;
    public Double c;
    public boolean d;

    public n(o sessionId, double d, Double d2, boolean z) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.a = sessionId;
        this.b = d;
        ((l) this).c = d2;
        this.d = z;
    }

    public static final String a(double d, n nVar) {
        return "End time '" + d + "' for session is less than the start time '" + nVar.b + "' for this session.";
    }

    public static final String b() {
        return "Caught exception creating Session Json.";
    }

    public final long c() {
        Double d = d();
        if (d == null) {
            return -1L;
        }
        final double dDoubleValue = d.doubleValue();
        long j = (long) (dDoubleValue - this.b);
        if (j < 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, new Function0() { // from class: com.braze.models.p
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    return n.a(dDoubleValue, this);
                }
            }, 6, (Object) null);
        }
        return j;
    }

    public Double d() {
        return this.c;
    }

    public String toString() {
        return "\nSession(sessionId=" + this.a + ", startTime=" + this.b + ", endTime=" + d() + ", isSealed=" + this.d + ", duration=" + c() + ')';
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("session_id", this.a);
            jSONObject.put("start_time", this.b);
            jSONObject.put("is_sealed", this.d);
            if (d() != null) {
                jSONObject.put("end_time", d());
                return jSONObject;
            }
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new j(28), 4, (Object) null);
        }
        return jSONObject;
    }

    public n(JSONObject sessionData) throws JSONException {
        Intrinsics.checkNotNullParameter(sessionData, "sessionData");
        String sessionId = sessionData.getString("session_id");
        Intrinsics.checkNotNullExpressionValue(sessionId, "getString(...)");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        UUID uuidFromString = UUID.fromString(sessionId);
        Intrinsics.checkNotNullExpressionValue(uuidFromString, "fromString(...)");
        this.a = new o(uuidFromString);
        this.b = sessionData.getDouble("start_time");
        this.d = sessionData.getBoolean("is_sealed");
        this.c = JsonUtils.getDoubleOrNull(sessionData, "end_time");
    }
}
