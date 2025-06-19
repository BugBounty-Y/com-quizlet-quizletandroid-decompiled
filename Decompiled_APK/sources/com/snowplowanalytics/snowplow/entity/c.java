package com.snowplowanalytics.snowplow.entity;

import java.util.HashMap;

/* loaded from: classes3.dex */
public final class c extends com.snowplowanalytics.snowplow.payload.a {
    public final HashMap b;

    public c(boolean z) {
        super("iglu:com.snowplowanalytics.mobile/application_lifecycle/jsonschema/1-0-0");
        HashMap map = new HashMap();
        this.b = map;
        map.put("isVisible", Boolean.valueOf(z));
        a(map);
    }
}
