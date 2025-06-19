package kotlin.sequences;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l extends kotlin.jvm.internal.r implements Function1 {
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        kotlin.random.e.a.getClass();
        return Integer.valueOf(kotlin.random.e.b.d(2147418112) + 65536);
    }
}
