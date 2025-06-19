package com.quizlet.quizletandroid.ui.onboarding;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class h extends w0 {
    public final m0 b;
    public final a c;
    public final s0 d;

    public h(m0 savedStateHandle, a repository, AbstractC5040y dispatcher) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = savedStateHandle;
        this.c = repository;
        this.d = e0.c(new d(e.a, null));
        QuestionnaireModel questionnaireModel = (QuestionnaireModel) savedStateHandle.a("questionnaire_model");
        if (questionnaireModel == null) {
            E.A(p0.j(this), dispatcher, null, new g(this, null), 2);
            return;
        }
        savedStateHandle.c(questionnaireModel, "questionnaire_model");
        f currentStep = new f(questionnaireModel);
        do {
            s0Var = this.d;
            value = s0Var.getValue();
            ((d) value).getClass();
            Intrinsics.checkNotNullParameter(currentStep, "currentStep");
        } while (!s0Var.k(value, new d(currentStep, null)));
    }
}
