package com.braze.coroutine;

import com.braze.support.BrazeLogger;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.a implements A {
    public e(C5041z c5041z) {
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        try {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) f.a, BrazeLogger.Priority.E, th, false, (Function0) new d(th), 4, (Object) null);
            com.braze.events.d dVar = f.b;
            if (dVar != null) {
                dVar.b(th, Throwable.class);
            }
        } catch (Exception unused) {
        }
    }
}
