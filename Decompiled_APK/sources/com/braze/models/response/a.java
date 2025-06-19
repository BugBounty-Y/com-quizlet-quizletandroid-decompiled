package com.braze.models.response;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public final com.braze.communication.d a;
    public final Long b;

    public a(com.braze.requests.n request, com.braze.communication.d connectionResult) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(connectionResult, "connectionResult");
        this.a = connectionResult;
        String str = (String) connectionResult.b.get("retry-after");
        this.b = str != null ? com.braze.support.l.a(str) : null;
    }
}
