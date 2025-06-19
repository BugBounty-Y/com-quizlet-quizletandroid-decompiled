package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.E1;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        WrittenQuestionGradingOption writtenQuestionGradingOption;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        G g = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.learn.usecase.d dVar = g.G;
            com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
            long j = fVar.u;
            DBStudySet dBStudySetE = fVar.e();
            String wordLang = dBStudySetE != null ? dBStudySetE.getWordLang() : null;
            DBStudySet dBStudySetE2 = fVar.e();
            String defLang = dBStudySetE2 != null ? dBStudySetE2.getDefLang() : null;
            this.j = 1;
            obj = dVar.a(j, wordLang, defLang, g.s, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        kotlinx.collections.immutable.c cVar = (kotlinx.collections.immutable.c) obj;
        com.quizlet.data.interactor.achievements.f fVar2 = g.H;
        com.quizlet.features.infra.basestudy.manager.f fVar3 = g.Z;
        com.quizlet.qutils.language.e eVarH = fVar2.h(fVar3);
        com.quizlet.qutils.language.e eVarE = g.I.e(fVar3);
        if (g.F.isEnabled()) {
            if (cVar.size() == 1) {
                writtenQuestionGradingOption = (WrittenQuestionGradingOption) CollectionsKt.K(cVar);
            } else if ((eVarH instanceof com.quizlet.qutils.language.c) && (eVarE instanceof com.quizlet.qutils.language.c) && !((com.quizlet.qutils.language.c) eVarH).a.equals(((com.quizlet.qutils.language.c) eVarE).a)) {
                writtenQuestionGradingOption = WrittenQuestionGradingOption.Strict.e;
            } else {
                WrittenQuestionGradingOption.Relaxed relaxed = WrittenQuestionGradingOption.Relaxed.e;
                writtenQuestionGradingOption = cVar.contains(relaxed) ? relaxed : WrittenQuestionGradingOption.Moderate.e;
            }
            com.quizlet.features.infra.studysetting.managers.a aVarG = fVar3.g();
            E1 e1 = E1.SMART_GRADING;
            if (!aVarG.k(e1)) {
                com.quizlet.features.infra.studysetting.managers.a aVarG2 = fVar3.g();
                boolean z = writtenQuestionGradingOption.d;
                aVarG2.getClass();
                aVarG2.m(e1, z);
            }
            com.quizlet.features.infra.studysetting.managers.a aVarG3 = fVar3.g();
            E1 e12 = E1.FLEXIBLE_GRADING_ACCEPT_ANSWERS_WITH_TYPOS;
            if (!aVarG3.k(e12)) {
                com.quizlet.features.infra.studysetting.managers.a aVarG4 = fVar3.g();
                boolean z2 = writtenQuestionGradingOption.c;
                aVarG4.getClass();
                aVarG4.m(e12, z2);
            }
        }
        return Unit.a;
    }
}
