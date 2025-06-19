package androidx.paging;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a1 implements kotlinx.coroutines.C, kotlinx.coroutines.channels.x {
    public final kotlinx.coroutines.channels.h a;
    public final /* synthetic */ kotlinx.coroutines.C b;

    public a1(kotlinx.coroutines.C scope, kotlinx.coroutines.channels.h channel) {
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(channel, "channel");
        this.a = channel;
        this.b = scope;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.b.getCoroutineContext();
    }

    @Override // kotlinx.coroutines.channels.x
    public final void n(Function1 handler) {
        Intrinsics.checkNotNullParameter(handler, "handler");
        this.a.n(handler);
    }

    @Override // kotlinx.coroutines.channels.x
    public final Object o(Object obj) {
        return this.a.o(obj);
    }

    @Override // kotlinx.coroutines.channels.x
    public final Object s(Object obj, kotlin.coroutines.h hVar) {
        return this.a.s(obj, hVar);
    }
}
