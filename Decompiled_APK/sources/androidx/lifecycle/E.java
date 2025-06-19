package androidx.lifecycle;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E implements H, kotlinx.coroutines.C {
    public final C a;
    public final CoroutineContext b;

    public E(C lifecycle, CoroutineContext coroutineContext) {
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        Intrinsics.checkNotNullParameter(coroutineContext, "coroutineContext");
        this.a = lifecycle;
        this.b = coroutineContext;
        if (((L) lifecycle).d == B.a) {
            kotlinx.coroutines.E.h(coroutineContext, null);
        }
    }

    @Override // androidx.lifecycle.H
    public final void d(J source, A event) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(event, "event");
        C c = this.a;
        if (((L) c).d.compareTo(B.a) <= 0) {
            c.b(this);
            kotlinx.coroutines.E.h(this.b, null);
        }
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.b;
    }
}
