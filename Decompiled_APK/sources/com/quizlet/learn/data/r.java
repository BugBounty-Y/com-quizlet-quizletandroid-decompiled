package com.quizlet.learn.data;

import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r extends AbstractC4550o {
    public final ShowQuestion.SelfAssessment a;

    public r(ShowQuestion.SelfAssessment question) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && Intrinsics.b(this.a, ((r) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowSelfAssessmentQuestion(question=" + this.a + ")";
    }
}
