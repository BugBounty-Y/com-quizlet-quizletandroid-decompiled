package androidx.lifecycle.viewmodel;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final C4950i a;
    public final Function1 b;

    public f(C4950i clazz, Function1 initializer) {
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        this.a = clazz;
        this.b = initializer;
    }
}
