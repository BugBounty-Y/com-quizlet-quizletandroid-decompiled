package kotlinx.serialization.modules;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.q0;

/* loaded from: classes3.dex */
public interface e {
    default void a(kotlin.reflect.c kClass) {
        q0 serializer = q0.a;
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        c(kClass, new com.sdk.growthbook.utils.a(27));
    }

    void c(kotlin.reflect.c cVar, com.sdk.growthbook.utils.a aVar);

    void d(kotlin.reflect.c cVar, Function1 function1);

    void e(kotlin.reflect.c cVar, kotlin.reflect.c cVar2, KSerializer kSerializer);

    void f(kotlin.reflect.c cVar, Function1 function1);
}
