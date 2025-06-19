package com.quizlet.learn.data;

import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q extends AbstractC4550o {
    public final ShowQuestion.MultipleChoice a;

    public q(ShowQuestion.MultipleChoice question) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowMultipleChoiceQuestion(question=" + this.a + ")";
    }
}
