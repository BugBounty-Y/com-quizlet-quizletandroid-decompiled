package androidx.compose.foundation.lazy.layout;

import java.util.Map;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k0 extends kotlin.jvm.internal.r implements Function2 {
    public static final k0 a = new k0(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Map mapB = ((l0) obj2).b();
        if (mapB.isEmpty()) {
            return null;
        }
        return mapB;
    }
}
