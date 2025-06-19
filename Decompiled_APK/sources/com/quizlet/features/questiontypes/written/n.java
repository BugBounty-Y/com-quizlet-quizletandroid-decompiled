package com.quizlet.features.questiontypes.written;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3455g;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ o k;
    public final /* synthetic */ AbstractC3455g l;
    public final /* synthetic */ StudiableQuestionGradedAnswer m;
    public final /* synthetic */ com.quizlet.features.questiontypes.basequestion.data.a n;
    public final /* synthetic */ boolean o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(o oVar, AbstractC3455g abstractC3455g, StudiableQuestionGradedAnswer studiableQuestionGradedAnswer, com.quizlet.features.questiontypes.basequestion.data.a aVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oVar;
        this.l = abstractC3455g;
        this.m = studiableQuestionGradedAnswer;
        this.n = aVar;
        this.o = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        com.quizlet.features.questiontypes.basequestion.data.a aVar = this.n;
        return new n(this.k, this.l, this.m, aVar, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        AbstractC3455g abstractC3455g;
        AbstractC3455g abstractC3455g2;
        StudiableQuestionGradedAnswer studiableQuestionGradedAnswer;
        QuestionSettings questionSettings;
        boolean z;
        boolean z2;
        com.quizlet.features.questiontypes.composables.d dVar;
        Object obj2;
        com.quizlet.features.questiontypes.composables.d dVar2;
        com.quizlet.features.questiontypes.basequestion.data.a aVar;
        com.quizlet.features.questiontypes.composables.d dVar3;
        com.quizlet.features.questiontypes.composables.d dVar4;
        Object obj3 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        AbstractC3455g abstractC3455g3 = this.l;
        o oVar = this.k;
        if (i == 0) {
            Z.e(obj);
            d0 d0Var = oVar.v;
            com.quizlet.features.questiontypes.basequestion.f fVar = new com.quizlet.features.questiontypes.basequestion.f(abstractC3455g3 instanceof com.quizlet.features.questiontypes.written.data.c);
            this.j = 1;
            if (d0Var.emit(fVar, this) == obj3) {
                return obj3;
            }
        } else {
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                return Unit.a;
            }
            Z.e(obj);
        }
        s0 s0Var = oVar.p;
        while (true) {
            Object value = s0Var.getValue();
            r rVar = (r) value;
            Intrinsics.e(rVar, "null cannot be cast to non-null type com.quizlet.features.questiontypes.written.WrittenUiState.ViewState");
            q qVar = (q) rVar;
            boolean z3 = oVar.k;
            AbstractC3455g abstractC3455g4 = z3 ? abstractC3455g3 : qVar.b;
            StudiableQuestionGradedAnswer studiableQuestionGradedAnswer2 = this.m;
            QuestionSettings questionSettings2 = oVar.l;
            boolean z4 = studiableQuestionGradedAnswer2.a;
            if (z3) {
                Boolean boolValueOf = Boolean.valueOf(z4);
                if (oVar.j == A1.TEST || !boolValueOf.equals(Boolean.FALSE) || !questionSettings2.r || z4) {
                    studiableQuestionGradedAnswer = studiableQuestionGradedAnswer2;
                    abstractC3455g2 = abstractC3455g4;
                    z2 = z3;
                    z = z4;
                    abstractC3455g = abstractC3455g3;
                    questionSettings = questionSettings2;
                    dVar4 = new com.quizlet.features.questiontypes.composables.d(R.string.continue_button, new com.quizlet.features.notes.paywall.a(0, oVar, o.class, "onContinueClick", "onContinueClick$questiontypes_release()V", 0, 17));
                } else {
                    dVar4 = new com.quizlet.features.questiontypes.composables.d(R.string.try_again_button, new com.quizlet.features.questionnaire.screens.c(5, oVar, studiableQuestionGradedAnswer2));
                    abstractC3455g = abstractC3455g3;
                    abstractC3455g2 = abstractC3455g4;
                    studiableQuestionGradedAnswer = studiableQuestionGradedAnswer2;
                    questionSettings = questionSettings2;
                    z = z4;
                    z2 = z3;
                }
                dVar = dVar4;
            } else {
                abstractC3455g = abstractC3455g3;
                abstractC3455g2 = abstractC3455g4;
                studiableQuestionGradedAnswer = studiableQuestionGradedAnswer2;
                questionSettings = questionSettings2;
                z = z4;
                z2 = z3;
                dVar = null;
            }
            if (this.o || !z2) {
                obj2 = obj3;
                dVar2 = null;
            } else {
                if (z) {
                    obj2 = obj3;
                    dVar3 = new com.quizlet.features.questiontypes.composables.d(R.string.override_i_was_incorrect_button, new com.quizlet.features.notes.paywall.a(0, oVar, o.class, "onIWasIncorrectClick", "onIWasIncorrectClick$questiontypes_release()V", 0, 18));
                } else {
                    obj2 = obj3;
                    dVar3 = new com.quizlet.features.questiontypes.composables.d(R.string.override_i_was_correct_button, new com.quizlet.features.notes.paywall.a(0, oVar, o.class, "onIWasCorrectClick", "onIWasCorrectClick$questiontypes_release()V", 0, 19));
                }
                dVar2 = dVar3;
            }
            aVar = this.n;
            if (s0Var.k(value, q.a(qVar, abstractC3455g2, aVar, dVar, dVar2))) {
                break;
            }
            abstractC3455g3 = abstractC3455g;
            obj3 = obj2;
        }
        boolean z5 = questionSettings.c;
        m mVar = new m(oVar, aVar, null);
        this.j = 2;
        Object objM = E.m(new com.quizlet.features.questiontypes.basequestion.b(z5, studiableQuestionGradedAnswer, mVar, oVar.d, null), this);
        if (objM != kotlin.coroutines.intrinsics.a.a) {
            objM = Unit.a;
        }
        Object obj4 = obj2;
        if (objM == obj4) {
            return obj4;
        }
        return Unit.a;
    }
}
