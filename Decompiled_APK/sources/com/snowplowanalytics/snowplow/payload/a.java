package com.snowplowanalytics.snowplow.payload;

import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class a {
    public final HashMap a;

    public a(b data) {
        Intrinsics.checkNotNullParameter("iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0", "schema");
        Intrinsics.checkNotNullParameter(data, "data");
        HashMap map = new HashMap();
        this.a = map;
        b("iglu:com.snowplowanalytics.mobile/screen/jsonschema/1-0-0");
        map.put("data", data.b);
    }

    public final void a(Object obj) {
        if (obj != null) {
            this.a.put("data", obj);
        }
    }

    public final void b(String schema) {
        Intrinsics.checkNotNullParameter(schema, "schema");
        if (schema.length() <= 0) {
            throw new IllegalArgumentException("schema cannot be empty");
        }
        this.a.put("schema", schema);
    }

    public final String toString() {
        String string = new JSONObject(this.a).toString();
        Intrinsics.checkNotNullExpressionValue(string, "JSONObject(payload).toString()");
        return string;
    }

    public a(String schema, Object data) {
        Intrinsics.checkNotNullParameter(schema, "schema");
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = new HashMap();
        b(schema);
        a(data);
    }

    public a(String schema) {
        Intrinsics.checkNotNullParameter(schema, "schema");
        this.a = new HashMap();
        b(schema);
        a(new HashMap());
    }
}
