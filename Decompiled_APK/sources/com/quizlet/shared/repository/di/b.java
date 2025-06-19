package com.quizlet.shared.repository.di;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.shared.repository.h;
import com.quizlet.shared.repository.i;
import com.quizlet.shared.repository.j;
import com.quizlet.shared.repository.studynotes.d;
import com.quizlet.shared.repository.studynotes.e;
import com.quizlet.shared.repository.studynotes.k;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class b extends r implements Function1 {
    public static final b a = new b(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        org.koin.core.module.a module = (org.koin.core.module.a) obj;
        Intrinsics.checkNotNullParameter(module, "$this$module");
        module.a(com.quizlet.shared.persistence.di.b.a, com.quizlet.shared.quizletapi.di.c.a);
        int i = 2;
        a aVar = new a(i, 0);
        org.koin.core.qualifier.a aVar2 = org.koin.core.registry.a.c;
        org.koin.core.definition.c cVar = org.koin.core.definition.c.b;
        K k = K.a;
        org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(h.class), null, aVar, cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
        org.koin.core.instance.a aVar3 = new org.koin.core.instance.a(beanDefinition);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar3, module, aVar3, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.a.class));
        org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(j.class), null, new a(i, 1), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
        org.koin.core.instance.a aVar4 = new org.koin.core.instance.a(beanDefinition2);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar4, module, aVar4, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.c.class));
        org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(i.class), null, new a(i, 2), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
        org.koin.core.instance.a aVar5 = new org.koin.core.instance.a(beanDefinition3);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar5, module, aVar5, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.b.class));
        org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.a.class), null, new a(i, 3), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
        org.koin.core.instance.a aVar6 = new org.koin.core.instance.a(beanDefinition4);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar6, module, aVar6, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.b.class));
        org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.j.class), null, new a(i, 4), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
        org.koin.core.instance.a aVar7 = new org.koin.core.instance.a(beanDefinition5);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar7, module, aVar7, "<this>"), kotlin.jvm.internal.K.a(d.class));
        org.koin.core.definition.b beanDefinition6 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.i.class), null, new a(i, 5), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition6, "beanDefinition");
        org.koin.core.instance.a aVar8 = new org.koin.core.instance.a(beanDefinition6);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar8, module, aVar8, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.studynotes.c.class));
        org.koin.core.definition.b beanDefinition7 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(k.class), null, new a(i, 6), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition7, "beanDefinition");
        org.koin.core.instance.a aVar9 = new org.koin.core.instance.a(beanDefinition7);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar9, module, aVar9, "<this>"), kotlin.jvm.internal.K.a(e.class));
        org.koin.core.definition.b beanDefinition8 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.k.class), null, new a(i, 7), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition8, "beanDefinition");
        org.koin.core.instance.a aVar10 = new org.koin.core.instance.a(beanDefinition8);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar10, module, aVar10, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.d.class));
        org.koin.core.definition.b beanDefinition9 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.repository.eligibility.b.class), null, new a(i, 8), cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition9, "beanDefinition");
        org.koin.core.instance.a aVar11 = new org.koin.core.instance.a(beanDefinition9);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar11, module, aVar11, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.repository.eligibility.a.class));
        return Unit.a;
    }
}
