package kotlin.collections;

import java.util.Collections;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class Z {
    public static kotlin.collections.builders.p a(kotlin.collections.builders.p builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        kotlin.collections.builders.h hVar = builder.a;
        hVar.b();
        return hVar.i > 0 ? builder : kotlin.collections.builders.p.c;
    }

    public static Set b(Object obj) {
        Set setSingleton = Collections.singleton(obj);
        Intrinsics.checkNotNullExpressionValue(setSingleton, "singleton(...)");
        return setSingleton;
    }
}
