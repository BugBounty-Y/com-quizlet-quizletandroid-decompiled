package io.ktor.client.plugins;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class V implements e0 {
    public final kotlin.jvm.functions.c a;
    public final e0 b;

    public V(kotlin.jvm.functions.c interceptor, e0 nextSender) {
        Intrinsics.checkNotNullParameter(interceptor, "interceptor");
        Intrinsics.checkNotNullParameter(nextSender, "nextSender");
        this.a = interceptor;
        this.b = nextSender;
    }

    @Override // io.ktor.client.plugins.e0
    public final Object a(io.ktor.client.request.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        return this.a.invoke(this.b, cVar, cVar2);
    }
}
