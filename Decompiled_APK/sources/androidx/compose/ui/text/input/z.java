package androidx.compose.ui.text.input;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class z extends kotlin.jvm.internal.r implements Function2 {
    public static final z a = new z(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        androidx.compose.runtime.saveable.b bVar = (androidx.compose.runtime.saveable.b) obj;
        A a2 = (A) obj2;
        return kotlin.collections.B.f(androidx.compose.ui.text.C.a(a2.a, androidx.compose.ui.text.C.a, bVar), androidx.compose.ui.text.C.a(new androidx.compose.ui.text.K(a2.b), androidx.compose.ui.text.C.p, bVar));
    }
}
