package com.quizlet.features.questiontypes.mcq.data;

import com.google.android.gms.internal.mlkit_vision_camera.Y2;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends Y2 {
    public final ArrayList a;
    public final com.quizlet.features.questiontypes.data.a b;
    public final StudiableQuestionGradedAnswer c;

    public c(ArrayList answers, com.quizlet.features.questiontypes.data.a labelState, StudiableQuestionGradedAnswer studiableQuestionGradedAnswer) {
        Intrinsics.checkNotNullParameter(answers, "answers");
        Intrinsics.checkNotNullParameter(labelState, "labelState");
        this.a = answers;
        this.b = labelState;
        this.c = studiableQuestionGradedAnswer;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_camera.Y2
    public final com.quizlet.features.questiontypes.data.a c() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a.equals(cVar.a) && this.b.equals(cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        StudiableQuestionGradedAnswer studiableQuestionGradedAnswer = this.c;
        return iHashCode + (studiableQuestionGradedAnswer == null ? 0 : studiableQuestionGradedAnswer.hashCode());
    }

    public final String toString() {
        return "StandardAnswer(answers=" + this.a + ", labelState=" + this.b + ", gradedAnswer=" + this.c + ")";
    }
}
