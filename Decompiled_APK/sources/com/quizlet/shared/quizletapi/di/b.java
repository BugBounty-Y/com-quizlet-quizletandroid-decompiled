package com.quizlet.shared.quizletapi.di;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.shared.quizletapi.studiableMetadata.d;
import com.quizlet.shared.quizletapi.studynotes.e;
import com.quizlet.shared.quizletapi.studynotes.f;
import com.quizlet.shared.quizletapi.studynotes.g;
import com.quizlet.shared.quizletapi.studynotes.i;
import com.quizlet.shared.quizletapi.studynotes.k;
import com.quizlet.shared.quizletapi.studynotes.m;
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
        int i = 2;
        org.koin.core.module.a module = (org.koin.core.module.a) obj;
        Intrinsics.checkNotNullParameter(module, "$this$module");
        module.a(com.quizlet.shared.httpclient.di.b.a, com.quizlet.shared.models.api.di.c.a);
        a aVar = a.b;
        org.koin.core.qualifier.a aVar2 = org.koin.core.registry.a.c;
        org.koin.core.definition.c cVar = org.koin.core.definition.c.a;
        K k = K.a;
        org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.b.class), null, aVar, cVar, k);
        Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
        org.koin.core.instance.c factory = new org.koin.core.instance.c(beanDefinition);
        module.b(factory);
        Intrinsics.checkNotNullParameter(module, "module");
        Intrinsics.checkNotNullParameter(factory, "factory");
        a aVar3 = new a(i, 4);
        org.koin.core.definition.c cVar2 = org.koin.core.definition.c.b;
        org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(d.class), null, aVar3, cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
        org.koin.core.instance.a aVar4 = new org.koin.core.instance.a(beanDefinition2);
        AbstractC3418z2.b(AbstractC4178x.n(module, aVar4, module, aVar4, "<this>"), new kotlin.reflect.c[]{kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.studiableMetadata.a.class), kotlin.jvm.internal.K.a(d.class)});
        org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.grading.d.class), null, new a(i, 5), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
        org.koin.core.instance.a aVar5 = new org.koin.core.instance.a(beanDefinition3);
        AbstractC3418z2.b(AbstractC4178x.n(module, aVar5, module, aVar5, "<this>"), new kotlin.reflect.c[]{kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.grading.a.class), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.grading.d.class)});
        org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.srs.d.class), null, new a(i, 6), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
        org.koin.core.instance.a aVar6 = new org.koin.core.instance.a(beanDefinition4);
        AbstractC3418z2.b(AbstractC4178x.n(module, aVar6, module, aVar6, "<this>"), new kotlin.reflect.c[]{kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.srs.a.class), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.srs.d.class)});
        org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.studyset.d.class), null, new a(i, 7), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
        org.koin.core.instance.a aVar7 = new org.koin.core.instance.a(beanDefinition5);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar7, module, aVar7, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.studyset.a.class));
        org.koin.core.definition.b beanDefinition6 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.studynotes.c.class), null, new a(i, 8), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition6, "beanDefinition");
        org.koin.core.instance.a aVar8 = new org.koin.core.instance.a(beanDefinition6);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar8, module, aVar8, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.studynotes.d.class));
        org.koin.core.definition.b beanDefinition7 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folderstudymaterials.d.class), null, new a(i, 9), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition7, "beanDefinition");
        org.koin.core.instance.a aVar9 = new org.koin.core.instance.a(beanDefinition7);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar9, module, aVar9, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folderstudymaterials.c.class));
        org.koin.core.definition.b beanDefinition8 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folders.a.class), null, new a(i, 10), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition8, "beanDefinition");
        org.koin.core.instance.a aVar10 = new org.koin.core.instance.a(beanDefinition8);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar10, module, aVar10, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folders.b.class));
        org.koin.core.definition.b beanDefinition9 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folderstudymaterials.a.class), null, new a(i, 11), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition9, "beanDefinition");
        org.koin.core.instance.a aVar11 = new org.koin.core.instance.a(beanDefinition9);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar11, module, aVar11, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.folderstudymaterials.b.class));
        org.koin.core.definition.b beanDefinition10 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(k.class), null, new a(i, 12), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition10, "beanDefinition");
        org.koin.core.instance.a aVar12 = new org.koin.core.instance.a(beanDefinition10);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar12, module, aVar12, "<this>"), kotlin.jvm.internal.K.a(f.class));
        org.koin.core.definition.b beanDefinition11 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(i.class), null, new a(i, 1), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition11, "beanDefinition");
        org.koin.core.instance.a aVar13 = new org.koin.core.instance.a(beanDefinition11);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar13, module, aVar13, "<this>"), kotlin.jvm.internal.K.a(e.class));
        org.koin.core.definition.b beanDefinition12 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(m.class), null, new a(i, i), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition12, "beanDefinition");
        org.koin.core.instance.a aVar14 = new org.koin.core.instance.a(beanDefinition12);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar14, module, aVar14, "<this>"), kotlin.jvm.internal.K.a(g.class));
        org.koin.core.definition.b beanDefinition13 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.eligibility.d.class), null, new a(i, 3), cVar2, k);
        Intrinsics.checkNotNullParameter(beanDefinition13, "beanDefinition");
        org.koin.core.instance.a aVar15 = new org.koin.core.instance.a(beanDefinition13);
        AbstractC3418z2.a(AbstractC4178x.n(module, aVar15, module, aVar15, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.quizletapi.eligibility.a.class));
        return Unit.a;
    }
}
