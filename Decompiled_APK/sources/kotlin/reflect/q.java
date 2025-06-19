package kotlin.reflect;

import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.U;

/* loaded from: classes3.dex */
public final class q {
    public q(DefaultConstructorMarker defaultConstructorMarker) {
    }

    public static KTypeProjection a(U type) {
        Intrinsics.checkNotNullParameter(type, "type");
        return new KTypeProjection(s.a, type);
    }
}
