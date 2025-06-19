package com.quizlet.features.questiontypes.basequestion;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class k extends com.quizlet.viewmodel.b implements j, i {
    public final com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a c;
    public final Y d;
    public final X e;
    public final X f;
    public final X g;
    public final X h;

    public k(m0 savedStateHandle, com.quizlet.quizletandroid.ui.studymodes.grader.b studiableQuestionGraderProvider, com.quizlet.quizletandroid.ui.studymodes.questionTypes.managers.a questionAnswerManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(studiableQuestionGraderProvider, "studiableQuestionGraderProvider");
        Intrinsics.checkNotNullParameter(questionAnswerManager, "questionAnswerManager");
        this.c = questionAnswerManager;
        z1 z1Var = A1.Companion;
        Object objA = savedStateHandle.a("study_mode_type_key");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA).intValue();
        z1Var.getClass();
        A1 a1A = z1.a(iIntValue);
        this.d = new Y();
        this.e = new X(1);
        this.f = new X(1);
        this.g = new X(1);
        this.h = new X(1);
        studiableQuestionGraderProvider.a(a1A);
    }
}
