package androidx.compose.foundation.lazy;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class t extends kotlin.jvm.internal.r implements Function2 {
    public static final t a = new t(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        A a2 = (A) obj2;
        return kotlin.collections.B.j(Integer.valueOf(a2.d.a()), Integer.valueOf(a2.d.b()));
    }
}
