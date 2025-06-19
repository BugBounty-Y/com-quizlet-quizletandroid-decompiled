package com.snowplowanalytics.core.globalcontexts;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final com.snowplowanalytics.snowplow.globalcontexts.a b;

    public a(String identifier, com.snowplowanalytics.snowplow.globalcontexts.a globalContext) {
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        Intrinsics.checkNotNullParameter(globalContext, "globalContext");
        this.a = identifier;
        this.b = globalContext;
    }
}
