package com.quizlet.shared.cache;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.mayakapps.kache.C4034c;
import com.mayakapps.kache.C4040i;
import com.mayakapps.kache.x;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class c extends kotlin.jvm.internal.r implements Function1 {
    public static final c b = new c(1, 0);
    public static final c c = new c(1, 1);
    public static final c d = new c(1, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                C4034c FileKache = (C4034c) obj;
                Intrinsics.checkNotNullParameter(FileKache, "$this$FileKache");
                x xVar = x.a;
                FileKache.getClass();
                Intrinsics.checkNotNullParameter(xVar, "<set-?>");
                FileKache.a = xVar;
                FileKache.c = 1;
                kotlinx.coroutines.internal.d dVarC = E.c(O.a);
                Intrinsics.checkNotNullParameter(dVarC, "<set-?>");
                FileKache.b = dVarC;
                break;
            case 1:
                C4040i InMemoryKache = (C4040i) obj;
                Intrinsics.checkNotNullParameter(InMemoryKache, "$this$InMemoryKache");
                x xVar2 = x.a;
                InMemoryKache.getClass();
                Intrinsics.checkNotNullParameter(xVar2, "<set-?>");
                InMemoryKache.a = xVar2;
                break;
            default:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                kotlinx.coroutines.scheduling.e eVar = O.a;
                org.koin.core.qualifier.a aVarB = AbstractC3410x2.b("inMemory");
                m mVar = new m(eVar, 0);
                org.koin.core.qualifier.a aVar = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar = org.koin.core.definition.c.a;
                K k = K.a;
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(a.class), aVarB, mVar, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.c factory = new org.koin.core.instance.c(beanDefinition);
                module.b(factory);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory, "factory");
                org.koin.core.qualifier.a aVarB2 = AbstractC3410x2.b("persistent");
                m mVar2 = new m(eVar, 1);
                org.koin.core.definition.c cVar2 = org.koin.core.definition.c.b;
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(a.class), aVarB2, mVar2, cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.a factory2 = new org.koin.core.instance.a(beanDefinition2);
                module.b(factory2);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory2, "factory");
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(a.class), AbstractC3410x2.b("expirable"), n.a, cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.a factory3 = new org.koin.core.instance.a(beanDefinition3);
                module.b(factory3);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory3, "factory");
                break;
        }
        return Unit.a;
    }
}
