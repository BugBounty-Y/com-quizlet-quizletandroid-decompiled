package com.quizlet.shared.cache;

import androidx.camera.camera2.internal.p0;
import androidx.compose.animation.T;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;

/* loaded from: classes3.dex */
public abstract class u {
    public static final kotlinx.serialization.json.q a;

    static {
        p0 builder = new p0();
        C4950i baseClass = K.a(serialization.e.class);
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        ArrayList arrayList = new ArrayList();
        C4950i subclass = K.a(ExpirableCacheEntry.class);
        KSerializer serializer = ExpirableCacheEntry.Companion.serializer();
        Intrinsics.checkNotNullParameter(subclass, "subclass");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        arrayList.add(new Pair(subclass, serializer));
        Intrinsics.checkNotNullParameter(builder, "builder");
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Pair pair = (Pair) it2.next();
            kotlin.reflect.c cVar = (kotlin.reflect.c) pair.a;
            KSerializer kSerializer = (KSerializer) pair.b;
            Intrinsics.e(cVar, "null cannot be cast to non-null type kotlin.reflect.KClass<Base of kotlinx.serialization.modules.PolymorphicModuleBuilder>");
            Intrinsics.e(kSerializer, "null cannot be cast to non-null type kotlinx.serialization.KSerializer<T of kotlinx.serialization.internal.Platform_commonKt.cast>");
            p0.l(builder, baseClass, cVar, kSerializer);
        }
        a = Y1.c(new T(builder.g(), false));
    }
}
