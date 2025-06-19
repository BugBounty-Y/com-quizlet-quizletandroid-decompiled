package com.quizlet.shared.usecase.di;

import com.quizlet.shared.usecase.folderstudymaterials.h;
import com.quizlet.shared.usecase.studynotes.o;
import com.quizlet.shared.usecase.studynotes.p;
import com.quizlet.shared.usecase.studynotes.s;
import com.quizlet.shared.usecase.studynotes.t;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class a extends r implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.login.a aVar = com.quizlet.shared.di.a.a;
                if (aVar != null) {
                    return ((org.koin.core.registry.a) aVar.a).b.a(null, K.a(com.quizlet.shared.usecase.grading.c.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 1:
                com.quizlet.data.repository.login.a aVar2 = com.quizlet.shared.di.a.a;
                if (aVar2 != null) {
                    return ((org.koin.core.registry.a) aVar2.a).b.a(null, K.a(com.quizlet.shared.usecase.studiableMetadata.g.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 2:
                com.quizlet.data.repository.login.a aVar3 = com.quizlet.shared.di.a.a;
                if (aVar3 != null) {
                    return ((org.koin.core.registry.a) aVar3.a).b.a(null, K.a(com.quizlet.shared.usecase.studiableMetadata.a.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 3:
                com.quizlet.data.repository.login.a aVar4 = com.quizlet.shared.di.a.a;
                if (aVar4 != null) {
                    return ((org.koin.core.registry.a) aVar4.a).b.a(null, K.a(com.quizlet.shared.usecase.srs.b.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 4:
                com.quizlet.data.repository.login.a aVar5 = com.quizlet.shared.di.a.a;
                if (aVar5 != null) {
                    return ((org.koin.core.registry.a) aVar5.a).b.a(null, K.a(com.quizlet.shared.usecase.eligibility.c.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 5:
                com.quizlet.data.repository.login.a aVar6 = com.quizlet.shared.di.a.a;
                if (aVar6 != null) {
                    return ((org.koin.core.registry.a) aVar6.a).b.a(null, K.a(com.quizlet.shared.usecase.session.c.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 6:
                com.quizlet.data.repository.login.a aVar7 = com.quizlet.shared.di.a.a;
                if (aVar7 != null) {
                    return ((org.koin.core.registry.a) aVar7.a).b.a(null, K.a(com.quizlet.shared.usecase.session.b.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 7:
                com.quizlet.data.repository.login.a aVar8 = com.quizlet.shared.di.a.a;
                if (aVar8 != null) {
                    return ((org.koin.core.registry.a) aVar8.a).b.a(null, K.a(o.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 8:
                com.quizlet.data.repository.login.a aVar9 = com.quizlet.shared.di.a.a;
                if (aVar9 != null) {
                    return ((org.koin.core.registry.a) aVar9.a).b.a(null, K.a(p.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 9:
                com.quizlet.data.repository.login.a aVar10 = com.quizlet.shared.di.a.a;
                if (aVar10 != null) {
                    return ((org.koin.core.registry.a) aVar10.a).b.a(null, K.a(com.quizlet.shared.usecase.studynotes.r.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 10:
                com.quizlet.data.repository.login.a aVar11 = com.quizlet.shared.di.a.a;
                if (aVar11 != null) {
                    return ((org.koin.core.registry.a) aVar11.a).b.a(null, K.a(t.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 11:
                com.quizlet.data.repository.login.a aVar12 = com.quizlet.shared.di.a.a;
                if (aVar12 != null) {
                    return ((org.koin.core.registry.a) aVar12.a).b.a(null, K.a(s.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 12:
                com.quizlet.data.repository.login.a aVar13 = com.quizlet.shared.di.a.a;
                if (aVar13 != null) {
                    return ((org.koin.core.registry.a) aVar13.a).b.a(null, K.a(com.quizlet.shared.usecase.folderstudymaterials.g.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 13:
                com.quizlet.data.repository.login.a aVar14 = com.quizlet.shared.di.a.a;
                if (aVar14 != null) {
                    return ((org.koin.core.registry.a) aVar14.a).b.a(null, K.a(h.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 14:
                com.quizlet.data.repository.login.a aVar15 = com.quizlet.shared.di.a.a;
                if (aVar15 != null) {
                    return ((org.koin.core.registry.a) aVar15.a).b.a(null, K.a(com.quizlet.shared.usecase.folderstudymaterials.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            default:
                com.quizlet.data.repository.login.a aVar16 = com.quizlet.shared.di.a.a;
                if (aVar16 != null) {
                    return ((org.koin.core.registry.a) aVar16.a).b.a(null, K.a(com.quizlet.shared.usecase.folderstudymaterials.f.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
        }
    }
}
