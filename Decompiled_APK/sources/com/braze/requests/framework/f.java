package com.braze.requests.framework;

import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f implements c {
    public static final String b(com.braze.models.response.g gVar) {
        return "Shutdown sync got success response: " + gVar;
    }

    @Override // com.braze.requests.framework.c
    public final void a(com.braze.models.response.g apiResponse) {
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.models.response.o(apiResponse, 2), 7, (Object) null);
    }

    public static final String b(com.braze.models.response.a aVar) {
        return "Shutdown sync got error response: " + aVar;
    }

    @Override // com.braze.requests.framework.c
    public final void a(com.braze.models.response.a apiResponse) {
        Intrinsics.checkNotNullParameter(apiResponse, "apiResponse");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(apiResponse, 1), 7, (Object) null);
    }
}
