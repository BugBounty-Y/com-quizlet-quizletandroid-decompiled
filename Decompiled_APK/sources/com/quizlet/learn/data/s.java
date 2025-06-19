package com.quizlet.learn.data;

import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s extends AbstractC4550o {
    public final ShowQuestion.Written a;

    public s(ShowQuestion.Written question) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && Intrinsics.b(this.a, ((s) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowWrittenQuestion(question=" + this.a + ")";
    }
}
