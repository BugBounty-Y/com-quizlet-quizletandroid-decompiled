package io.ktor.utils.io;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class B implements C {
    public final t a;
    public final CoroutineContext b;

    public B(t channel, CoroutineContext coroutineContext) {
        Intrinsics.checkNotNullParameter(channel, "channel");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        this.a = channel;
        this.b = coroutineContext;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.b;
    }
}
