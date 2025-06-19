package com.quizlet.learn.data;

import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4553p extends AbstractC4550o {
    public final ShowQuestion.FillInTheBlank a;

    public C4553p(ShowQuestion.FillInTheBlank question) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4553p) && Intrinsics.b(this.a, ((C4553p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShowFillInTheBlankQuestion(question=" + this.a + ")";
    }
}
