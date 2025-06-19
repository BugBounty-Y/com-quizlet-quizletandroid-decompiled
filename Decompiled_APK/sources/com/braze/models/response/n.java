package com.braze.models.response;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n extends a {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(com.braze.requests.n request, com.braze.communication.d connectionResult) {
        super(request, connectionResult);
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(connectionResult, "connectionResult");
    }
}
