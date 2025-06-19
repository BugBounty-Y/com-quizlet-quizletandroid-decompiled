package com.snowplowanalytics.snowplow.network;

import androidx.compose.animation.d0;
import androidx.transition.C1405h;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import okhttp3.C5083l;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class a {
    public final C5083l a;

    public a(C5083l cookie) {
        Intrinsics.checkNotNullParameter(cookie, "cookie");
        this.a = cookie;
    }

    public final String a() {
        StringBuilder sb = new StringBuilder();
        C5083l c5083l = this.a;
        sb.append(c5083l.f ? "https" : "http");
        sb.append("://");
        sb.append(c5083l.d);
        sb.append(c5083l.e);
        sb.append('|');
        sb.append(c5083l.a);
        return sb.toString();
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        String str = aVar.a.a;
        C5083l c5083l = this.a;
        return Intrinsics.b(str, c5083l.a) && Intrinsics.b(aVar.a.d, c5083l.d) && Intrinsics.b(aVar.a.e, c5083l.e);
    }

    public final int hashCode() {
        C5083l c5083l = this.a;
        return c5083l.e.hashCode() + d0.e(d0.e(527, 31, c5083l.a), 31, c5083l.d);
    }

    public a(String serialized) throws JSONException {
        Intrinsics.checkNotNullParameter(serialized, "serialized");
        JSONObject jSONObject = new JSONObject(serialized);
        String name = jSONObject.getString("name");
        Intrinsics.checkNotNullExpressionValue(name, "`object`.getString(\"name\")");
        Intrinsics.checkNotNullParameter(name, "name");
        if (Intrinsics.b(StringsKt.g0(name).toString(), name)) {
            String value = jSONObject.getString("value");
            Intrinsics.checkNotNullExpressionValue(value, "`object`.getString(\"value\")");
            Intrinsics.checkNotNullParameter(value, "value");
            if (Intrinsics.b(StringsKt.g0(value).toString(), value)) {
                long j = jSONObject.getLong("expiresAt");
                j = j <= 0 ? Long.MIN_VALUE : j;
                j = j > 253402300799999L ? 253402300799999L : j;
                String domain = jSONObject.getString("domain");
                Intrinsics.checkNotNullExpressionValue(domain, "`object`.getString(\"domain\")");
                Intrinsics.checkNotNullParameter(domain, "domain");
                String strD = C1405h.d(domain);
                if (strD != null) {
                    String path = jSONObject.getString("path");
                    Intrinsics.checkNotNullExpressionValue(path, "`object`.getString(\"path\")");
                    Intrinsics.checkNotNullParameter(path, "path");
                    if (D.r(path, "/", false)) {
                        this.a = new C5083l(name, value, j, strD, path, false, false, true, false);
                        return;
                    }
                    throw new IllegalArgumentException("path must start with '/'");
                }
                throw new IllegalArgumentException("unexpected domain: ".concat(domain));
            }
            throw new IllegalArgumentException("value is not trimmed");
        }
        throw new IllegalArgumentException("name is not trimmed");
    }
}
