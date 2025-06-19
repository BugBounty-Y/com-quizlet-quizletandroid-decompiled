package kotlin.internal.jdk7;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class b extends kotlin.internal.b {
    @Override // kotlin.internal.b
    public final void a(Throwable cause, Throwable exception) {
        Intrinsics.checkNotNullParameter(cause, "cause");
        Intrinsics.checkNotNullParameter(exception, "exception");
        Integer num = a.b;
        if (num == null || num.intValue() >= 19) {
            cause.addSuppressed(exception);
        } else {
            super.a(cause, exception);
        }
    }
}
