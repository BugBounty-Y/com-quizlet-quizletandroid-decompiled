package kotlinx.coroutines.flow.internal;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public final class G implements kotlin.coroutines.h, kotlin.coroutines.jvm.internal.d {
    public final kotlin.coroutines.h a;
    public final CoroutineContext b;

    public G(kotlin.coroutines.h hVar, CoroutineContext coroutineContext) {
        this.a = hVar;
        this.b = coroutineContext;
    }

    @Override // kotlin.coroutines.jvm.internal.d
    public final kotlin.coroutines.jvm.internal.d getCallerFrame() {
        kotlin.coroutines.h hVar = this.a;
        if (hVar instanceof kotlin.coroutines.jvm.internal.d) {
            return (kotlin.coroutines.jvm.internal.d) hVar;
        }
        return null;
    }

    @Override // kotlin.coroutines.h
    public final CoroutineContext getContext() {
        return this.b;
    }

    @Override // kotlin.coroutines.h
    public final void resumeWith(Object obj) {
        this.a.resumeWith(obj);
    }
}
