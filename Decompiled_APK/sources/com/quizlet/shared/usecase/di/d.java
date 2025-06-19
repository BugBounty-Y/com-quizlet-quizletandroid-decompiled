package com.quizlet.shared.usecase.di;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.shared.usecase.studiableMetadata.h;
import com.quizlet.shared.usecase.studynotes.j;
import com.quizlet.shared.usecase.studynotes.l;
import com.quizlet.shared.usecase.studynotes.n;
import com.quizlet.shared.usecase.studynotes.o;
import com.quizlet.shared.usecase.studynotes.p;
import com.quizlet.shared.usecase.studynotes.q;
import com.quizlet.shared.usecase.studynotes.s;
import com.quizlet.shared.usecase.studynotes.t;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class d extends r implements Function1 {
    public static final d b = new d(1, 0);
    public static final d c = new d(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                module.a(com.quizlet.shared.repository.di.c.a);
                c cVar = c.b;
                org.koin.core.qualifier.a aVar = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar2 = org.koin.core.definition.c.b;
                K k = K.a;
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(n.class), null, cVar, cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.a factory = new org.koin.core.instance.a(beanDefinition);
                module.b(factory);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory, "factory");
                int i = 2;
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.grading.b.class), null, new c(i, 3), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.a aVar2 = new org.koin.core.instance.a(beanDefinition2);
                AbstractC3418z2.a(AbstractC4178x.n(module, aVar2, module, aVar2, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.grading.c.class));
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studiableMetadata.a.class), null, new c(i, 4), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.a aVar3 = new org.koin.core.instance.a(beanDefinition3);
                module.b(aVar3);
                Intrinsics.checkNotNullParameter(new org.koin.core.definition.d(module, aVar3), "<this>");
                org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studiableMetadata.d.class), null, new c(i, 5), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
                org.koin.core.instance.a aVar4 = new org.koin.core.instance.a(beanDefinition4);
                AbstractC3418z2.a(AbstractC4178x.n(module, aVar4, module, aVar4, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studiableMetadata.g.class));
                org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studiableMetadata.f.class), null, new c(i, 6), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
                org.koin.core.instance.a aVar5 = new org.koin.core.instance.a(beanDefinition5);
                AbstractC3418z2.a(AbstractC4178x.n(module, aVar5, module, aVar5, "<this>"), kotlin.jvm.internal.K.a(h.class));
                org.koin.core.definition.b beanDefinition6 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.srs.a.class), null, new c(i, 7), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition6, "beanDefinition");
                org.koin.core.instance.a aVar6 = new org.koin.core.instance.a(beanDefinition6);
                AbstractC3418z2.a(AbstractC4178x.n(module, aVar6, module, aVar6, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.srs.b.class));
                org.koin.core.definition.b beanDefinition7 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.eligibility.b.class), null, new c(i, 8), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition7, "beanDefinition");
                org.koin.core.instance.a aVar7 = new org.koin.core.instance.a(beanDefinition7);
                AbstractC3418z2.a(AbstractC4178x.n(module, aVar7, module, aVar7, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.eligibility.c.class));
                break;
            default:
                org.koin.core.module.a module2 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module2, "$this$module");
                module2.a(com.quizlet.shared.repository.di.c.a, com.quizlet.shared.repository.g.d);
                int i2 = 2;
                c cVar3 = new c(i2, 10);
                org.koin.core.qualifier.a aVar8 = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar4 = org.koin.core.definition.c.b;
                K k2 = K.a;
                org.koin.core.definition.b beanDefinition8 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studynotes.h.class), null, cVar3, cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition8, "beanDefinition");
                org.koin.core.instance.a aVar9 = new org.koin.core.instance.a(beanDefinition8);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar9, module2, aVar9, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studynotes.r.class));
                org.koin.core.definition.b beanDefinition9 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studynotes.f.class), null, new c(i2, 11), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition9, "beanDefinition");
                org.koin.core.instance.a aVar10 = new org.koin.core.instance.a(beanDefinition9);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar10, module2, aVar10, "<this>"), kotlin.jvm.internal.K.a(q.class));
                org.koin.core.definition.b beanDefinition10 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(l.class), null, new c(i2, 12), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition10, "beanDefinition");
                org.koin.core.instance.a aVar11 = new org.koin.core.instance.a(beanDefinition10);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar11, module2, aVar11, "<this>"), kotlin.jvm.internal.K.a(t.class));
                org.koin.core.definition.b beanDefinition11 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(j.class), null, new c(i2, 13), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition11, "beanDefinition");
                org.koin.core.instance.a aVar12 = new org.koin.core.instance.a(beanDefinition11);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar12, module2, aVar12, "<this>"), kotlin.jvm.internal.K.a(s.class));
                org.koin.core.definition.b beanDefinition12 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studynotes.b.class), null, new c(i2, 14), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition12, "beanDefinition");
                org.koin.core.instance.a aVar13 = new org.koin.core.instance.a(beanDefinition12);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar13, module2, aVar13, "<this>"), kotlin.jvm.internal.K.a(o.class));
                org.koin.core.definition.b beanDefinition13 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.studynotes.d.class), null, new c(i2, 15), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition13, "beanDefinition");
                org.koin.core.instance.a aVar14 = new org.koin.core.instance.a(beanDefinition13);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar14, module2, aVar14, "<this>"), kotlin.jvm.internal.K.a(p.class));
                org.koin.core.definition.b beanDefinition14 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.c.class), null, new c(i2, 16), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition14, "beanDefinition");
                org.koin.core.instance.a aVar15 = new org.koin.core.instance.a(beanDefinition14);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar15, module2, aVar15, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.g.class));
                org.koin.core.definition.b beanDefinition15 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.d.class), null, new c(i2, 17), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition15, "beanDefinition");
                org.koin.core.instance.a aVar16 = new org.koin.core.instance.a(beanDefinition15);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar16, module2, aVar16, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.h.class));
                org.koin.core.definition.b beanDefinition16 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.a.class), null, new c(i2, 18), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition16, "beanDefinition");
                org.koin.core.instance.a aVar17 = new org.koin.core.instance.a(beanDefinition16);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar17, module2, aVar17, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.e.class));
                org.koin.core.definition.b beanDefinition17 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.b.class), null, new c(i2, 9), cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition17, "beanDefinition");
                org.koin.core.instance.a aVar18 = new org.koin.core.instance.a(beanDefinition17);
                AbstractC3418z2.a(AbstractC4178x.n(module2, aVar18, module2, aVar18, "<this>"), kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.folderstudymaterials.f.class));
                org.koin.core.definition.b beanDefinition18 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.session.b.class), null, c.c, cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition18, "beanDefinition");
                org.koin.core.instance.a factory2 = new org.koin.core.instance.a(beanDefinition18);
                module2.b(factory2);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory2, "factory");
                org.koin.core.definition.b beanDefinition19 = new org.koin.core.definition.b(aVar8, kotlin.jvm.internal.K.a(com.quizlet.shared.usecase.session.c.class), null, c.d, cVar4, k2);
                Intrinsics.checkNotNullParameter(beanDefinition19, "beanDefinition");
                org.koin.core.instance.a factory3 = new org.koin.core.instance.a(beanDefinition19);
                module2.b(factory3);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory3, "factory");
                break;
        }
        return Unit.a;
    }
}
