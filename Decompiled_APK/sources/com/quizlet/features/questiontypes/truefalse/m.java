package com.quizlet.features.questiontypes.truefalse;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m {
    public final com.quizlet.features.questiontypes.data.d a;
    public final com.quizlet.features.questiontypes.data.d b;
    public final d c;
    public final com.quizlet.features.questiontypes.basequestion.data.a d;

    public m(com.quizlet.features.questiontypes.data.d topPrompt, com.quizlet.features.questiontypes.data.d bottomPrompt, d answerState, com.quizlet.features.questiontypes.basequestion.data.a gradedState) {
        Intrinsics.checkNotNullParameter(topPrompt, "topPrompt");
        Intrinsics.checkNotNullParameter(bottomPrompt, "bottomPrompt");
        Intrinsics.checkNotNullParameter(answerState, "answerState");
        Intrinsics.checkNotNullParameter(gradedState, "gradedState");
        this.a = topPrompt;
        this.b = bottomPrompt;
        this.c = answerState;
        this.d = gradedState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b) && Intrinsics.b(this.c, mVar.c) && this.d == mVar.d;
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "TrueFalseUiState(topPrompt=" + this.a + ", bottomPrompt=" + this.b + ", answerState=" + this.c + ", gradedState=" + this.d + ")";
    }
}
