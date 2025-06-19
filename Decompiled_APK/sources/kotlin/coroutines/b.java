package kotlin.coroutines;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b implements l {
    public final Function1 a;
    public final l b;

    public b(l baseKey, Function1 safeCast) {
        Intrinsics.checkNotNullParameter(baseKey, "baseKey");
        Intrinsics.checkNotNullParameter(safeCast, "safeCast");
        this.a = safeCast;
        this.b = baseKey instanceof b ? ((b) baseKey).b : baseKey;
    }
}
