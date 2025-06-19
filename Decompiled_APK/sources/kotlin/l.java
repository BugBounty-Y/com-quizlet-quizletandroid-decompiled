package kotlin;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class l {
    public static k a(m mode, Function0 initializer) {
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        int iOrdinal = mode.ordinal();
        if (iOrdinal == 0) {
            return new u(initializer, null, 2, null);
        }
        if (iOrdinal == 1) {
            Intrinsics.checkNotNullParameter(initializer, "initializer");
            t tVar = new t();
            tVar.a = initializer;
            tVar.b = F.a;
            return tVar;
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        J j = new J();
        j.a = initializer;
        j.b = F.a;
        return j;
    }

    public static u b(Function0 initializer) {
        Intrinsics.checkNotNullParameter(initializer, "initializer");
        return new u(initializer, null, 2, null);
    }
}
