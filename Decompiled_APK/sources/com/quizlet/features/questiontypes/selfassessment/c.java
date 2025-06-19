package com.quizlet.features.questiontypes.selfassessment;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            Z.e(obj);
            RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion = hVar.g;
            com.quizlet.features.infra.models.flashcards.f fVarB = h.B(hVar, revealSelfAssessmentStudiableQuestion.b, revealSelfAssessmentStudiableQuestion);
            RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion2 = hVar.g;
            com.quizlet.features.questiontypes.selfassessment.data.a aVar2 = new com.quizlet.features.questiontypes.selfassessment.data.a(fVarB, h.B(hVar, revealSelfAssessmentStudiableQuestion2.c, revealSelfAssessmentStudiableQuestion2));
            this.j = 1;
            s0 s0Var = hVar.h;
            s0Var.getClass();
            s0Var.m(null, aVar2);
            if (Unit.a == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        if (hVar.o.c) {
            hVar.D();
        }
        return Unit.a;
    }
}
