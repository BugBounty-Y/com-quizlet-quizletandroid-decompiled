package androidx.lifecycle.viewmodel.internal;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class a implements AutoCloseable, C {
    public final CoroutineContext a;

    public a(CoroutineContext coroutineContext) {
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        this.a = coroutineContext;
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        E.h(this.a, null);
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.a;
    }
}
