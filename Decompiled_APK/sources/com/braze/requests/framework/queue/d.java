package com.braze.requests.framework.queue;

import com.braze.requests.framework.o;
import com.braze.requests.m;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends com.braze.requests.framework.b {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(m destination, com.braze.dispatch.h dispatchDataProvider) {
        super(destination, dispatchDataProvider);
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(dispatchDataProvider, "dispatchDataProvider");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new o(destination, 2), 7, (Object) null);
    }

    @Override // com.braze.requests.framework.b
    public final void a(long j) {
    }

    public static final String a(m mVar) {
        return "Default queue created for dest " + mVar;
    }
}
