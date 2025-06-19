package com.snowplowanalytics.snowplow.event;

import java.util.HashMap;
import java.util.Map;

/* loaded from: classes3.dex */
public final class c extends a {
    public Integer b;

    @Override // com.snowplowanalytics.snowplow.event.a
    public final Map a() {
        HashMap map = new HashMap();
        Integer num = this.b;
        if (num != null) {
            map.put("foregroundIndex", Integer.valueOf(num.intValue()));
        }
        return map;
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final String b() {
        return "iglu:com.snowplowanalytics.snowplow/application_foreground/jsonschema/1-0-0";
    }
}
