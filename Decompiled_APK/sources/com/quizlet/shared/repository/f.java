package com.quizlet.shared.repository;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.quizlet.shared.cache.o;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class f extends r implements Function1 {
    public static final f b = new f(1, 0);
    public static final f c = new f(1, 1);
    public static final f d = new f(1, 2);
    public static final f e = new f(1, 3);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                module.a(g.b, com.quizlet.shared.quizletapi.di.c.a, o.a, g.a, g.c);
                e eVar = e.b;
                org.koin.core.qualifier.a aVar = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar = org.koin.core.definition.c.b;
                K k = K.a;
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folders.a.class), null, eVar, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.a factory = new org.koin.core.instance.a(beanDefinition);
                module.b(factory);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory, "factory");
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.c.class), null, e.c, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.a factory2 = new org.koin.core.instance.a(beanDefinition2);
                module.b(factory2);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory2, "factory");
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.b.class), null, e.d, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.a factory3 = new org.koin.core.instance.a(beanDefinition3);
                module.b(factory3);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory3, "factory");
                org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.f.class), null, e.e, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
                org.koin.core.instance.a factory4 = new org.koin.core.instance.a(beanDefinition4);
                module.b(factory4);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory4, "factory");
                break;
            case 1:
                org.koin.core.module.a module2 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module2, "$this$module");
                e eVar2 = e.j;
                org.koin.core.qualifier.a aVar2 = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar2 = org.koin.core.definition.c.b;
                K k2 = K.a;
                org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.user.a.class), null, eVar2, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
                org.koin.core.instance.a factory5 = new org.koin.core.instance.a(beanDefinition5);
                module2.b(factory5);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory5, "factory");
                org.koin.core.definition.b beanDefinition6 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folders.e.class), null, e.k, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition6, "beanDefinition");
                org.koin.core.instance.a factory6 = new org.koin.core.instance.a(beanDefinition6);
                module2.b(factory6);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory6, "factory");
                org.koin.core.definition.b beanDefinition7 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folders.f.class), null, e.l, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition7, "beanDefinition");
                org.koin.core.instance.a factory7 = new org.koin.core.instance.a(beanDefinition7);
                module2.b(factory7);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory7, "factory");
                org.koin.core.definition.b beanDefinition8 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folders.g.class), null, e.m, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition8, "beanDefinition");
                org.koin.core.instance.a factory8 = new org.koin.core.instance.a(beanDefinition8);
                module2.b(factory8);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory8, "factory");
                org.koin.core.definition.b beanDefinition9 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studyset.a.class), null, e.n, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition9, "beanDefinition");
                org.koin.core.instance.a factory9 = new org.koin.core.instance.a(beanDefinition9);
                module2.b(factory9);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory9, "factory");
                org.koin.core.definition.b beanDefinition10 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.explanations.explanationquestions.a.class), null, e.o, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition10, "beanDefinition");
                org.koin.core.instance.a factory10 = new org.koin.core.instance.a(beanDefinition10);
                module2.b(factory10);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory10, "factory");
                org.koin.core.definition.b beanDefinition11 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.explanations.textbooks.a.class), null, e.p, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition11, "beanDefinition");
                org.koin.core.instance.a factory11 = new org.koin.core.instance.a(beanDefinition11);
                module2.b(factory11);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory11, "factory");
                org.koin.core.definition.b beanDefinition12 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.explanations.textbookexercises.a.class), null, e.q, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition12, "beanDefinition");
                org.koin.core.instance.a factory12 = new org.koin.core.instance.a(beanDefinition12);
                module2.b(factory12);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory12, "factory");
                org.koin.core.definition.b beanDefinition13 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.f.class), null, e.r, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition13, "beanDefinition");
                org.koin.core.instance.a factory13 = new org.koin.core.instance.a(beanDefinition13);
                module2.b(factory13);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory13, "factory");
                org.koin.core.definition.b beanDefinition14 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.g.class), null, e.f, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition14, "beanDefinition");
                org.koin.core.instance.a factory14 = new org.koin.core.instance.a(beanDefinition14);
                module2.b(factory14);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory14, "factory");
                org.koin.core.definition.b beanDefinition15 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.h.class), null, e.g, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition15, "beanDefinition");
                org.koin.core.instance.a factory15 = new org.koin.core.instance.a(beanDefinition15);
                module2.b(factory15);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory15, "factory");
                org.koin.core.definition.b beanDefinition16 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.e.class), null, e.h, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition16, "beanDefinition");
                org.koin.core.instance.a factory16 = new org.koin.core.instance.a(beanDefinition16);
                module2.b(factory16);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory16, "factory");
                org.koin.core.definition.b beanDefinition17 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.d.class), null, e.i, cVar2, k2);
                Intrinsics.checkNotNullParameter(beanDefinition17, "beanDefinition");
                org.koin.core.instance.a factory17 = new org.koin.core.instance.a(beanDefinition17);
                module2.b(factory17);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory17, "factory");
                break;
            case 2:
                org.koin.core.module.a module3 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module3, "$this$module");
                e eVar3 = e.s;
                org.koin.core.qualifier.a aVar3 = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar3 = org.koin.core.definition.c.b;
                K k3 = K.a;
                org.koin.core.definition.b beanDefinition18 = new org.koin.core.definition.b(aVar3, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folders.d.class), null, eVar3, cVar3, k3);
                Intrinsics.checkNotNullParameter(beanDefinition18, "beanDefinition");
                org.koin.core.instance.a factory18 = new org.koin.core.instance.a(beanDefinition18);
                module3.b(factory18);
                Intrinsics.checkNotNullParameter(module3, "module");
                Intrinsics.checkNotNullParameter(factory18, "factory");
                org.koin.core.definition.b beanDefinition19 = new org.koin.core.definition.b(aVar3, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.folderstudymaterials.a.class), null, e.t, cVar3, k3);
                Intrinsics.checkNotNullParameter(beanDefinition19, "beanDefinition");
                org.koin.core.instance.a factory19 = new org.koin.core.instance.a(beanDefinition19);
                module3.b(factory19);
                Intrinsics.checkNotNullParameter(module3, "module");
                Intrinsics.checkNotNullParameter(factory19, "factory");
                break;
            default:
                org.koin.core.module.a module4 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module4, "$this$module");
                org.koin.core.qualifier.a aVarB = AbstractC3410x2.b("data-layer-json");
                e eVar4 = e.u;
                org.koin.core.definition.b beanDefinition20 = new org.koin.core.definition.b(org.koin.core.registry.a.c, kotlin.jvm.internal.K.a(kotlinx.serialization.json.c.class), aVarB, eVar4, org.koin.core.definition.c.b, K.a);
                Intrinsics.checkNotNullParameter(beanDefinition20, "beanDefinition");
                org.koin.core.instance.a factory20 = new org.koin.core.instance.a(beanDefinition20);
                module4.b(factory20);
                Intrinsics.checkNotNullParameter(module4, "module");
                Intrinsics.checkNotNullParameter(factory20, "factory");
                break;
        }
        return Unit.a;
    }
}
