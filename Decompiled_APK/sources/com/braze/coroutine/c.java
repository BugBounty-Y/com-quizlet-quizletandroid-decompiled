package com.braze.coroutine;

import com.braze.support.BrazeLogger;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.a implements A {
    public c(C5041z c5041z) {
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) throws Throwable {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeCoroutineScope brazeCoroutineScope = BrazeCoroutineScope.INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) brazeCoroutineScope, BrazeLogger.Priority.E, th, false, (Function0) new a(th), 4, (Object) null);
        if (brazeCoroutineScope.getShouldReRaiseExceptions$android_sdk_base_release()) {
            throw th;
        }
    }
}
