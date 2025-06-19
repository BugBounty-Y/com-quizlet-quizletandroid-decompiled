package androidx.datastore.core;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b0 {
    public final Function2 a;
    public final kotlinx.coroutines.r b;
    public final l0 c;
    public final CoroutineContext d;

    public b0(Function2 transform, kotlinx.coroutines.r ack, l0 l0Var, CoroutineContext callerContext) {
        Intrinsics.checkNotNullParameter(transform, "transform");
        Intrinsics.checkNotNullParameter(ack, "ack");
        Intrinsics.checkNotNullParameter(callerContext, "callerContext");
        this.a = transform;
        this.b = ack;
        this.c = l0Var;
        this.d = callerContext;
    }
}
