package com.quizlet.explanations.feedback.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import com.quizlet.data.repository.activitycenter.b;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import com.quizlet.explanations.feedback.data.c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class a extends com.quizlet.viewmodel.a {
    public final b d;
    public final ExplanationsLogger e;
    public final Y f;
    public final X g;
    public ExplanationsFeedbackSetUpState h;

    public a(b sendFeedbackUseCase, ExplanationsLogger explanationsLogger) {
        Intrinsics.checkNotNullParameter(sendFeedbackUseCase, "sendFeedbackUseCase");
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        this.d = sendFeedbackUseCase;
        this.e = explanationsLogger;
        this.f = new Y(c.a);
        this.g = new X(1);
    }
}
