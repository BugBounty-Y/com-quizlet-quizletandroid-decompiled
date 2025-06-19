package com.braze.coroutine;

import com.braze.configuration.h;
import com.braze.support.BrazeLogger;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.O;

@Metadata
/* loaded from: classes.dex */
public final class BrazeCoroutineScope implements C {
    public static final BrazeCoroutineScope INSTANCE = new BrazeCoroutineScope();
    private static final CoroutineContext coroutineContext;
    private static final A exceptionHandler;
    private static boolean shouldReRaiseExceptions;

    static {
        c cVar = new c(C5041z.a);
        exceptionHandler = cVar;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        coroutineContext = kotlinx.coroutines.scheduling.d.b.plus(cVar).plus(E.e());
    }

    private BrazeCoroutineScope() {
    }

    public static final void cancelChildren() {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeCoroutineScope brazeCoroutineScope = INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) brazeCoroutineScope, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new h(1), 6, (Object) null);
        E.l(brazeCoroutineScope.getCoroutineContext());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String cancelChildren$lambda$1() {
        return "Cancelling children of BrazeCoroutineScope";
    }

    public static /* synthetic */ InterfaceC5025j0 launchDelayed$default(BrazeCoroutineScope brazeCoroutineScope, Number number, CoroutineContext coroutineContext2, Function1 function1, int i, Object obj) {
        if ((i & 2) != 0) {
            coroutineContext2 = brazeCoroutineScope.getCoroutineContext();
        }
        return brazeCoroutineScope.launchDelayed(number, coroutineContext2, function1);
    }

    @Override // kotlinx.coroutines.C
    public CoroutineContext getCoroutineContext() {
        return coroutineContext;
    }

    public final boolean getShouldReRaiseExceptions$android_sdk_base_release() {
        return shouldReRaiseExceptions;
    }

    public final InterfaceC5025j0 launchDelayed(Number startDelayInMs, CoroutineContext specificContext, Function1<? super kotlin.coroutines.h<? super Unit>, ? extends Object> block) {
        Intrinsics.checkNotNullParameter(startDelayInMs, "startDelayInMs");
        Intrinsics.checkNotNullParameter(specificContext, "specificContext");
        Intrinsics.checkNotNullParameter(block, "block");
        return E.A(this, specificContext, null, new b(startDelayInMs, block, null), 2);
    }
}
