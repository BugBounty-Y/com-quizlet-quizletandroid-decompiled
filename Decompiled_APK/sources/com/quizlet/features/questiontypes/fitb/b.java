package com.quizlet.features.questiontypes.fitb;

import androidx.compose.animation.core.J0;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends J0 {
    public final String c;
    public final String d;
    public final com.quizlet.features.questiontypes.data.a e;
    public final com.quizlet.features.questiontypes.fitb.ui.c f;
    public final com.quizlet.features.questiontypes.fitb.ui.b g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(String submittedAnswer, String correctAnswer, com.quizlet.features.questiontypes.data.a labelState) {
        super(8);
        Intrinsics.checkNotNullParameter(submittedAnswer, "submittedAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(labelState, "labelState");
        this.c = submittedAnswer;
        this.d = correctAnswer;
        this.e = labelState;
        this.f = new com.quizlet.features.questiontypes.fitb.ui.c(submittedAnswer);
        this.g = new com.quizlet.features.questiontypes.fitb.ui.b(correctAnswer);
    }

    @Override // androidx.compose.animation.core.J0
    public final com.quizlet.features.questiontypes.fitb.ui.e B() {
        return this.f;
    }

    @Override // androidx.compose.animation.core.J0
    public final com.quizlet.features.questiontypes.fitb.ui.e E() {
        return this.g;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(this.c.hashCode() * 31, 31, this.d);
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "Incorrect(submittedAnswer=" + this.c + ", correctAnswer=" + this.d + ", labelState=" + this.e + ")";
    }

    @Override // androidx.compose.animation.core.J0
    public final com.quizlet.features.questiontypes.data.a x() {
        return this.e;
    }
}
