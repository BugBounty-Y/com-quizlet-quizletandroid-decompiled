package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import com.quizlet.studiablemodels.MultipleChoiceStudiableQuestion;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestion;
import com.quizlet.studiablemodels.StudiableQuestionMetadata;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;
    public final /* synthetic */ StudiableQuestion l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(G g, StudiableQuestion studiableQuestion, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
        this.l = studiableQuestion;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new F(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object written;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        StudiableQuestion studiableQuestion = this.l;
        G g = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            TestStudyModeConfig testStudyModeConfig = g.E;
            if (testStudyModeConfig == null) {
                throw new IllegalArgumentException("Required value was null.");
            }
            StudiableQuestionMetadata studiableQuestionMetadataA = studiableQuestion.a();
            studiableQuestionMetadataA.getClass();
            boolean z = studiableQuestionMetadataA.d == assistantMode.enums.m.d;
            boolean z2 = studiableQuestion instanceof MultipleChoiceStudiableQuestion;
            boolean z3 = testStudyModeConfig.e;
            com.quizlet.features.infra.basestudy.manager.f fVar = g.D;
            if (z2) {
                DBSession dBSession = g.K;
                Intrinsics.d(dBSession);
                written = new ShowQuestion.MultipleChoice((MultipleChoiceStudiableQuestion) studiableQuestion, dBSession.getId(), fVar.u, g.E(), A1.TEST, z3, z, false);
            } else if (studiableQuestion instanceof TrueFalseStudiableQuestion) {
                DBSession dBSession2 = g.K;
                Intrinsics.d(dBSession2);
                written = new ShowQuestion.TrueFalse((TrueFalseStudiableQuestion) studiableQuestion, dBSession2.getId(), fVar.u, g.E(), A1.TEST, z3);
            } else {
                if (!(studiableQuestion instanceof WrittenStudiableQuestion)) {
                    if (!(studiableQuestion instanceof RevealSelfAssessmentStudiableQuestion) && !(studiableQuestion instanceof FillInTheBlankStudiableQuestion) && !(studiableQuestion instanceof MixedOptionMatchingStudiableQuestion)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    throw new IllegalArgumentException("Unsupported question type for Test study mode: " + studiableQuestion);
                }
                WrittenStudiableQuestion writtenStudiableQuestion = (WrittenStudiableQuestion) studiableQuestion;
                DBSession dBSession3 = g.K;
                Intrinsics.d(dBSession3);
                long id = dBSession3.getId();
                long j = fVar.u;
                QuestionSettings questionSettingsE = g.E();
                A1 a1 = A1.TEST;
                InterfaceC4176w0 interfaceC4176w0 = g.I;
                if (interfaceC4176w0 == null) {
                    Intrinsics.m("testMeteredEvent");
                    throw null;
                }
                written = new ShowQuestion.Written(writtenStudiableQuestion, id, j, questionSettingsE, a1, z3, interfaceC4176w0, false);
            }
            if (written == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            written = obj;
        }
        g.s.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.q(g.B, g.e.a.size(), studiableQuestion instanceof WrittenStudiableQuestion, (ShowQuestion) written));
        return Unit.a;
    }
}
