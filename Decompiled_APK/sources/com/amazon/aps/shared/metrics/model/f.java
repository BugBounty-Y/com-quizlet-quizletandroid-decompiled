package com.amazon.aps.shared.metrics.model;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class f extends i {
    public final m d;
    public final String e;
    public Boolean f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(m result, String hostname) {
        super(result, 0L, 6);
        Intrinsics.checkNotNullParameter(result, "result");
        Intrinsics.checkNotNullParameter(hostname, "hostname");
        this.d = result;
        this.e = hostname;
    }

    @Override // com.amazon.aps.shared.metrics.model.i
    public final m a() {
        return this.d;
    }

    @Override // com.amazon.aps.shared.metrics.model.i
    public final JSONObject b() throws JSONException {
        JSONObject jSONObjectB = super.b();
        jSONObjectB.put("h", this.e);
        Boolean bool = this.f;
        if (bool == null) {
            return jSONObjectB;
        }
        jSONObjectB.put("rf", bool.booleanValue());
        return jSONObjectB;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.d == fVar.d && Intrinsics.b(this.e, fVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + (this.d.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ApsMetricsPerfAaxBidEvent(result=");
        sb.append(this.d);
        sb.append(", hostname=");
        return d0.r(sb, this.e, ')');
    }
}
