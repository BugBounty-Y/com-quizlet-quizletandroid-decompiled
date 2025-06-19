package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class R0 extends kotlin.jvm.internal.r implements Function1 {
    public static final R0 a = new R0(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Function0 it2 = (Function0) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        it2.invoke();
        return Unit.a;
    }
}
