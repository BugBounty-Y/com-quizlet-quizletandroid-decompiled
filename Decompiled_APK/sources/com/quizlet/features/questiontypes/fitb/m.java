package com.quizlet.features.questiontypes.fitb;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.N2;
import com.google.android.gms.internal.mlkit_vision_camera.Q2;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.Z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class m extends w0 {
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a b;
    public final com.quizlet.billing.register.a c;
    public final com.quizlet.data.repository.login.a d;
    public final long e;
    public final FillInTheBlankStudiableQuestion f;
    public final com.quizlet.studiablemodels.grading.d g;
    public final s0 h;
    public final Z i;
    public final d0 j;
    public final d0 k;
    public final d0 l;
    public final Y m;
    public DBAnswer n;

    public m(m0 savedStateHandle, com.quizlet.quizletandroid.ui.studymodes.grader.b questionGraderProvider, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a questionAnswerManager, com.quizlet.billing.register.a studyModeSharedPreferencesManager, com.quizlet.data.repository.login.a useCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(questionGraderProvider, "questionGraderProvider");
        Intrinsics.checkNotNullParameter(questionAnswerManager, "questionAnswerManager");
        Intrinsics.checkNotNullParameter(studyModeSharedPreferencesManager, "studyModeSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(useCase, "useCase");
        this.b = questionAnswerManager;
        this.c = studyModeSharedPreferencesManager;
        this.d = useCase;
        Object objA = savedStateHandle.a("ARG_SET_ID");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.e = ((Number) objA).longValue();
        Object objA2 = savedStateHandle.a("ARG_STUDY_MODE_TYPE");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        z1 z1Var = A1.Companion;
        int iIntValue = ((Number) objA2).intValue();
        z1Var.getClass();
        A1 a1A = z1.a(iIntValue);
        Object objA3 = savedStateHandle.a("ARG_STUDIABLE_QUESTION");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        FillInTheBlankStudiableQuestion question = (FillInTheBlankStudiableQuestion) objA3;
        this.f = question;
        this.g = questionGraderProvider.a(a1A);
        Intrinsics.checkNotNullParameter(question, "question");
        useCase.b = question;
        N2 n2B = com.quizlet.features.questiontypes.helpers.a.b(question);
        useCase.c = n2B;
        s0 s0VarC = e0.c(new g(n2B, AbstractC3409x1.i(question.e), c.c, com.quizlet.features.questiontypes.basequestion.data.a.a, null, null));
        this.h = s0VarC;
        this.i = new Z(s0VarC);
        d0 d0VarB = e0.b(0, 1, null, 5);
        this.j = d0VarB;
        this.k = d0VarB;
        d0 d0VarB2 = e0.b(0, 0, null, 7);
        this.l = d0VarB2;
        this.m = new Y(d0VarB2);
        E.A(p0.j(this), null, null, new i(this, null), 3);
    }

    public final void A(Q2 event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (event.equals(o.a)) {
            E.A(p0.j(this), null, null, new j(null, this, null), 3);
            return;
        }
        if (event instanceof q) {
            E.A(p0.j(this), null, null, new j(A.b(((q) event).a), this, null), 3);
        } else if (event.equals(n.a)) {
            E.A(p0.j(this), null, null, new h(1200L, this, null), 3);
        } else {
            if (!event.equals(p.a)) {
                throw new NoWhenBranchMatchedException();
            }
            E.A(p0.j(this), null, null, new l(this, null), 3);
        }
    }
}
