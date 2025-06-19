package com.braze.triggers.config;

import com.braze.models.IPutIntoJson;
import com.braze.support.BrazeLogger;
import com.braze.support.v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c implements IPutIntoJson {
    public final long a;
    public final long b;
    public final int c;
    public final int d;
    public final int e;
    public final b f;
    public final int g;

    public c(JSONObject json) {
        Intrinsics.checkNotNullParameter(json, "json");
        this.a = json.optLong("start_time", -1L);
        this.b = json.optLong("end_time", -1L);
        this.c = json.optInt("priority", 0);
        this.g = json.optInt("min_seconds_since_last_trigger", -1);
        this.d = json.optInt("delay", 0);
        this.e = json.optInt("timeout", -1);
        this.f = new b(json);
    }

    public static final String b() {
        return "Could not convert ScheduleConfig to JSON";
    }

    @Override // com.braze.models.IPutIntoJson
    public final JSONObject forJsonPut() throws JSONException {
        try {
            JSONObject jSONObjectForJsonPut = this.f.forJsonPut();
            if (jSONObjectForJsonPut == null) {
                return null;
            }
            jSONObjectForJsonPut.put("start_time", this.a);
            jSONObjectForJsonPut.put("end_time", this.b);
            jSONObjectForJsonPut.put("priority", this.c);
            jSONObjectForJsonPut.put("min_seconds_since_last_trigger", this.g);
            jSONObjectForJsonPut.put("timeout", this.e);
            jSONObjectForJsonPut.put("delay", this.d);
            return jSONObjectForJsonPut;
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new v(29), 4, (Object) null);
            return null;
        }
    }
}
