package com.quizlet.shared.models.api.di;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class b extends r implements Function1 {
    public static final b a = new b(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        org.koin.core.module.a module = (org.koin.core.module.a) obj;
        Intrinsics.checkNotNullParameter(module, "$this$module");
        a aVar = a.a;
        org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(org.koin.core.registry.a.c, K.a(kotlinx.serialization.json.c.class), null, aVar, org.koin.core.definition.c.a, kotlin.collections.K.a);
        Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
        org.koin.core.instance.c factory = new org.koin.core.instance.c(beanDefinition);
        module.b(factory);
        Intrinsics.checkNotNullParameter(module, "module");
        Intrinsics.checkNotNullParameter(factory, "factory");
        return Unit.a;
    }
}
