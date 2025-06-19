package kotlin.jvm.internal;

import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.reflect.KTypeProjection;

/* loaded from: classes3.dex */
public final class T extends r implements Function1 {
    public final /* synthetic */ U a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(U u) {
        super(1);
        this.a = u;
    }

    @Override // kotlin.jvm.functions.Function1
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final CharSequence invoke(KTypeProjection it2) {
        String strValueOf;
        Intrinsics.checkNotNullParameter(it2, "it");
        this.a.getClass();
        if (it2.a == null) {
            return "*";
        }
        U u = it2.b;
        U u2 = u != null ? u : null;
        if (u2 == null || (strValueOf = u2.c(true)) == null) {
            strValueOf = String.valueOf(u);
        }
        int iOrdinal = it2.a.ordinal();
        if (iOrdinal == 0) {
            return strValueOf;
        }
        if (iOrdinal == 1) {
            return "in ".concat(strValueOf);
        }
        if (iOrdinal == 2) {
            return "out ".concat(strValueOf);
        }
        throw new NoWhenBranchMatchedException();
    }
}
