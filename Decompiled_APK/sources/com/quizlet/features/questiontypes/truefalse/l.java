package com.quizlet.features.questiontypes.truefalse;

import androidx.compose.ui.node.B;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import assistantMode.enums.EnumC1452f;
import com.google.android.gms.internal.mlkit_vision_barcode.B6;
import com.google.android.gms.internal.mlkit_vision_camera.s3;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.eventlogger.features.basequestion.QuestionEventLogger;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import com.quizlet.studiablemodels.QuestionSectionData;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import com.quizlet.studiablemodels.TrueFalseStudiableQuestion;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class l extends w0 implements b {
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a b;
    public final com.quizlet.data.repository.set.f c;
    public final QuestionEventLogger d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final String f;
    public final long g;
    public final A1 h;
    public final TrueFalseStudiableQuestion i;
    public final boolean j;
    public final com.quizlet.studiablemodels.grading.d k;
    public final s0 l;
    public final Z m;
    public final s0 n;
    public final Z o;
    public final d0 p;
    public final Y q;
    public DBAnswer r;
    public y0 s;

    public l(m0 savedStateHandle, com.quizlet.quizletandroid.ui.studymodes.grader.b questionGraderProvider, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a questionAnswerManager, com.quizlet.data.repository.set.f useCase, QuestionEventLogger questionEventLogger, com.quizlet.quizletandroid.managers.audio.h audioManager) {
        com.quizlet.features.infra.models.a aVarF;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(questionGraderProvider, "questionGraderProvider");
        Intrinsics.checkNotNullParameter(questionAnswerManager, "questionAnswerManager");
        Intrinsics.checkNotNullParameter(useCase, "useCase");
        Intrinsics.checkNotNullParameter(questionEventLogger, "questionEventLogger");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        this.b = questionAnswerManager;
        this.c = useCase;
        this.d = questionEventLogger;
        this.e = audioManager;
        this.f = B.f("toString(...)");
        Object objA = savedStateHandle.a("ARG_SET_ID");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = ((Number) objA).longValue();
        Object objA2 = savedStateHandle.a("ARG_STUDY_MODE_TYPE");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        z1 z1Var = A1.Companion;
        int iIntValue = ((Number) objA2).intValue();
        z1Var.getClass();
        A1 a1A = z1.a(iIntValue);
        this.h = a1A;
        Object objA3 = savedStateHandle.a("ARG_STUDIABLE_QUESTION");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        TrueFalseStudiableQuestion question = (TrueFalseStudiableQuestion) objA3;
        this.i = question;
        Object objA4 = savedStateHandle.a("ARG_SHOW_FEEDBACK");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.j = ((Boolean) objA4).booleanValue();
        this.k = questionGraderProvider.a(a1A);
        Intrinsics.checkNotNullParameter(question, "question");
        useCase.b = (com.quizlet.features.questiontypes.data.d) com.quizlet.features.questiontypes.helpers.a.b(question);
        Intrinsics.checkNotNullParameter(question, "<this>");
        QuestionSectionData questionSectionData = question.c;
        Intrinsics.e(questionSectionData, "null cannot be cast to non-null type com.quizlet.studiablemodels.DefaultQuestionSectionData");
        DefaultQuestionSectionData defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
        assistantMode.enums.m mVar = question.d.d;
        StudiableImage studiableImage = defaultQuestionSectionData.b;
        StudiableText studiableText = defaultQuestionSectionData.a;
        if (studiableText != null) {
            aVarF = B6.f(studiableText, mVar != assistantMode.enums.m.c && studiableImage == null);
        } else {
            aVarF = null;
        }
        useCase.c = new com.quizlet.features.questiontypes.data.d(aVarF, studiableImage);
        com.quizlet.features.questiontypes.composables.a aVar = com.quizlet.features.questiontypes.composables.a.a;
        d dVar = new d(aVar, aVar, new com.quizlet.features.questiontypes.data.a(R.string.answer_label_choose_the_answer, null));
        useCase.d = dVar;
        com.quizlet.features.questiontypes.data.d dVar2 = (com.quizlet.features.questiontypes.data.d) useCase.b;
        if (dVar2 == null) {
            Intrinsics.m("topPrompt");
            throw null;
        }
        com.quizlet.features.questiontypes.data.d dVar3 = (com.quizlet.features.questiontypes.data.d) useCase.c;
        if (dVar3 == null) {
            Intrinsics.m("bottomPrompt");
            throw null;
        }
        s0 s0VarC = e0.c(new m(dVar2, dVar3, dVar, com.quizlet.features.questiontypes.basequestion.data.a.a));
        this.l = s0VarC;
        this.m = new Z(s0VarC);
        s0 s0VarC2 = e0.c(new a(false, false));
        this.n = s0VarC2;
        this.o = new Z(s0VarC2);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.p = d0VarB;
        this.q = new Y(d0VarB);
        EnumC1452f enumC1452f = EnumC1452f.d;
    }

    public static final Unit A(l lVar, boolean z, c cVar) {
        s0 s0Var = lVar.n;
        boolean z2 = false;
        boolean z3 = cVar == c.a && z;
        if (cVar == c.b && z) {
            z2 = true;
        }
        a aVar = new a(z3, z2);
        s0Var.getClass();
        s0Var.m(null, aVar);
        Unit unit = Unit.a;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        return unit;
    }

    public final void B(s3 event) {
        DefaultQuestionSectionData defaultQuestionSectionData;
        Intrinsics.checkNotNullParameter(event, "event");
        if (event instanceof q) {
            E.A(p0.j(this), null, null, new h(this, ((q) event).a, null), 3);
            return;
        }
        if (!(event instanceof p)) {
            if (event.equals(o.a)) {
                E.A(p0.j(this), null, null, new j(this, null), 3);
                return;
            } else {
                if (!event.equals(n.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                E.A(p0.j(this), null, null, new i(this, null), 3);
                return;
            }
        }
        p pVar = (p) event;
        TrueFalseStudiableQuestion trueFalseStudiableQuestion = this.i;
        if (trueFalseStudiableQuestion.d.a()) {
            return;
        }
        c cVar = pVar.a;
        int iOrdinal = cVar.ordinal();
        if (iOrdinal == 0) {
            QuestionSectionData questionSectionData = trueFalseStudiableQuestion.b;
            Intrinsics.e(questionSectionData, "null cannot be cast to non-null type com.quizlet.studiablemodels.DefaultQuestionSectionData");
            defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData;
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            QuestionSectionData questionSectionData2 = trueFalseStudiableQuestion.c;
            Intrinsics.e(questionSectionData2, "null cannot be cast to non-null type com.quizlet.studiablemodels.DefaultQuestionSectionData");
            defaultQuestionSectionData = (DefaultQuestionSectionData) questionSectionData2;
        }
        y0 y0Var = this.s;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.s = E.A(p0.j(this), new androidx.compose.ui.text.font.o(C5041z.a, 4), null, new k(defaultQuestionSectionData, this, cVar, null), 2);
    }
}
