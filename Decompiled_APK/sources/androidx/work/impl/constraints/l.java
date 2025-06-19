package androidx.work.impl.constraints;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class l extends r implements Function1 {
    public static final l a = new l(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.work.impl.constraints.controllers.e it2 = (androidx.work.impl.constraints.controllers.e) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        String simpleName = it2.getClass().getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "it.javaClass.simpleName");
        return simpleName;
    }
}
