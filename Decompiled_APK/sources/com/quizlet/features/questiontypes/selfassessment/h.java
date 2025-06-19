package com.quizlet.features.questiontypes.selfassessment;

import androidx.compose.ui.node.B;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import com.quizlet.studiablemodels.StudiableAudio;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class h extends com.quizlet.viewmodel.b {
    public final QuestionEventLogger c;
    public final com.quizlet.features.infra.basestudy.data.models.onboarding.a d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a f;
    public final RevealSelfAssessmentStudiableQuestion g;
    public final s0 h;
    public final Z i;
    public final s0 j;
    public final Z k;
    public final d0 l;
    public final Y m;
    public com.quizlet.features.infra.models.flashcards.h n;
    public QuestionSettings o;
    public final long p;
    public final String q;

    public h(m0 savedStateHandle, QuestionEventLogger laModeEventLogger, com.quizlet.features.infra.basestudy.data.models.onboarding.a onboardingState, com.quizlet.quizletandroid.managers.audio.h audioManager, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a questionAnswerManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(laModeEventLogger, "laModeEventLogger");
        Intrinsics.checkNotNullParameter(onboardingState, "onboardingState");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        Intrinsics.checkNotNullParameter(questionAnswerManager, "questionAnswerManager");
        this.c = laModeEventLogger;
        this.d = onboardingState;
        this.e = audioManager;
        this.f = questionAnswerManager;
        Object objA = savedStateHandle.a("ARG_STUDIABLE_QUESTION");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = (RevealSelfAssessmentStudiableQuestion) objA;
        s0 s0VarC = e0.c(com.quizlet.features.questiontypes.selfassessment.data.b.a);
        this.h = s0VarC;
        this.i = new Z(s0VarC);
        s0 s0VarC2 = e0.c(Boolean.FALSE);
        this.j = s0VarC2;
        this.k = new Z(s0VarC2);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.l = d0VarB;
        this.m = new Y(d0VarB);
        this.n = com.quizlet.features.infra.models.flashcards.h.a;
        Object objA2 = savedStateHandle.a("ARG_SETTINGS");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.o = (QuestionSettings) objA2;
        Object objA3 = savedStateHandle.a("ARG_SET_ID");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.p = ((Number) objA3).longValue();
        this.q = B.f("toString(...)");
        E.A(p0.j(this), null, null, new c(this, null), 3);
    }

    public static final com.quizlet.features.infra.models.flashcards.f B(h hVar, QuestionSectionData questionSectionData, RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion) {
        hVar.getClass();
        return new com.quizlet.features.infra.models.flashcards.f(com.quizlet.features.infra.basestudy.helper.a.a(questionSectionData, revealSelfAssessmentStudiableQuestion.d.e), new G(1, hVar, h.class, "onAudioClicked", "onAudioClicked(Lcom/quizlet/studiablemodels/StudiableAudio;)V", 0, 22));
    }

    public static final void C(h hVar, RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion, boolean z) throws Exception {
        com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a aVar = hVar.f;
        long j = hVar.p;
        DBAnswer dBAnswerB = aVar.b(revealSelfAssessmentStudiableQuestion, z ? 1 : 0, j);
        E.A(p0.j(hVar), null, null, new d(hVar, dBAnswerB, aVar.c(dBAnswerB, revealSelfAssessmentStudiableQuestion, j), null), 3);
    }

    public final void D() {
        QuestionSectionData questionSectionData;
        int iOrdinal = this.n.ordinal();
        RevealSelfAssessmentStudiableQuestion revealSelfAssessmentStudiableQuestion = this.g;
        if (iOrdinal == 0) {
            questionSectionData = revealSelfAssessmentStudiableQuestion.b;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            questionSectionData = revealSelfAssessmentStudiableQuestion.c;
        }
        DefaultQuestionSectionData defaultQuestionSectionData = questionSectionData instanceof DefaultQuestionSectionData ? (DefaultQuestionSectionData) questionSectionData : null;
        StudiableAudio studiableAudio = defaultQuestionSectionData != null ? defaultQuestionSectionData.c : null;
        if (studiableAudio != null) {
            String str = studiableAudio.a;
            if (StringsKt.O(str)) {
                return;
            }
            E.A(p0.j(this), new C4203d(this), null, new g(this, str, null), 2);
        }
    }
}
