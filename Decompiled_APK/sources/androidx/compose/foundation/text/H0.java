package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.EnumC0320d0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class H0 extends kotlin.jvm.internal.r implements Function2 {
    public static final H0 a = new H0(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        I0 i0 = (I0) obj2;
        return kotlin.collections.B.j(Float.valueOf(i0.a()), Boolean.valueOf(((EnumC0320d0) ((androidx.compose.runtime.L0) i0.e).getValue()) == EnumC0320d0.a));
    }
}
