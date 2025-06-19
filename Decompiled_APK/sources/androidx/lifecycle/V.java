package androidx.lifecycle;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class V {
    public final C1249j a;
    public final CoroutineContext b;

    public V(C1249j target, CoroutineContext context) {
        Intrinsics.checkNotNullParameter(target, "target");
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = target;
        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
        this.b = context.plus(kotlinx.coroutines.internal.m.a.e);
    }
}
