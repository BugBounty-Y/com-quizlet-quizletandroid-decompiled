package io.ktor.client.plugins.api;

import io.ktor.client.plugins.e0;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class g implements C {
    public final e0 a;
    public final CoroutineContext b;

    public g(e0 httpSendSender, CoroutineContext coroutineContext) {
        Intrinsics.checkNotNullParameter(httpSendSender, "httpSendSender");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        this.a = httpSendSender;
        this.b = coroutineContext;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.b;
    }
}
