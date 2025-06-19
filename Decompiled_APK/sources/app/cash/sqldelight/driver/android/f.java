package app.cash.sqldelight.driver.android;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class f extends r implements Function1 {
    public static final f a = new f(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        j execute = (j) obj;
        Intrinsics.checkNotNullParameter(execute, "$this$execute");
        return Long.valueOf(execute.a());
    }
}
