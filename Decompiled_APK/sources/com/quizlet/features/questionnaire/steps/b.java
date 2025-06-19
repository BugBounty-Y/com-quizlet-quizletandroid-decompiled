package com.quizlet.features.questionnaire.steps;

import androidx.lifecycle.w0;
import com.quizlet.features.questionnaire.navigation.StepModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends w0 {
    public final StepModel.Intro b;
    public final com.quizlet.data.interactor.course.a c;

    public b(StepModel.Intro model, com.quizlet.data.interactor.course.a shim) {
        Intrinsics.checkNotNullParameter(model, "model");
        Intrinsics.checkNotNullParameter(shim, "shim");
        this.b = model;
        this.c = shim;
    }
}
