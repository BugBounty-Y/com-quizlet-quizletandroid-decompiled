package com.snowplowanalytics.core.tracker;

import java.util.Map;
import kotlin.collections.V;

/* loaded from: classes3.dex */
public final class b extends com.snowplowanalytics.snowplow.event.a {
    public static final /* synthetic */ int b = 0;

    @Override // com.snowplowanalytics.snowplow.event.a
    public final Map a() {
        return V.c();
    }

    @Override // com.snowplowanalytics.snowplow.event.a
    public final String b() {
        return "iglu:com.snowplowanalytics.mobile/application_install/jsonschema/1-0-0";
    }
}
