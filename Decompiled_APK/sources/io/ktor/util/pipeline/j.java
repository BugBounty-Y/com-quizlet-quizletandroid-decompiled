package io.ktor.util.pipeline;

import kotlin.coroutines.CoroutineContext;
import kotlin.coroutines.n;

/* loaded from: classes3.dex */
public final class j implements kotlin.coroutines.jvm.internal.d, kotlin.coroutines.h {
    public static final j a = new j();

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        return null;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return n.a;
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        throw new IllegalStateException("Failed to capture stack frame. This is usually happens when a coroutine is running so the frame stack is changing quickly and the coroutine debug agent is unable to capture it concurrently. You may retry running your test to see this particular trace.");
    }
}
