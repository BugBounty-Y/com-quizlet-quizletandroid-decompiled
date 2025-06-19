package com.snowplowanalytics.snowplow.emitter;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final com.snowplowanalytics.snowplow.payload.b a;
    public final long b;

    public b(com.snowplowanalytics.snowplow.payload.b payload, long j) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.a = payload;
        this.b = j;
    }
}
