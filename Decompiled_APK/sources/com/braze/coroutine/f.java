package com.braze.coroutine;

import com.braze.configuration.h;
import com.braze.support.BrazeLogger;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C4975b0;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class f implements C {
    public static final f a = new f();
    public static com.braze.events.d b;
    public static final CoroutineContext c;

    static {
        e eVar = new e(C5041z.a);
        ExecutorService executorServiceNewSingleThreadExecutor = Executors.newSingleThreadExecutor();
        Intrinsics.checkNotNullExpressionValue(executorServiceNewSingleThreadExecutor, "newSingleThreadExecutor(...)");
        c = new C4975b0(executorServiceNewSingleThreadExecutor).plus(eVar).plus(E.e());
    }

    public static final String b() {
        return "Cancelling children of SerialCoroutineScope";
    }

    public final void a() {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new h(2), 6, (Object) null);
        E.l(c);
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return c;
    }
}
