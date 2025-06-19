package com.snowplowanalytics.snowplow.event;

import java.util.HashMap;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends a {
    public final Map b;
    public final String c;

    public f(com.snowplowanalytics.snowplow.payload.a eventData) {
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        HashMap map = eventData.a;
        Object obj = map.get("data");
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.collections.Map<kotlin.String, kotlin.Any?>");
        this.b = (Map) obj;
        Object obj2 = map.get("schema");
        Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.String");
        this.c = (String) obj2;
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final Map a() {
        return this.b;
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final String b() {
        return this.c;
    }
}
