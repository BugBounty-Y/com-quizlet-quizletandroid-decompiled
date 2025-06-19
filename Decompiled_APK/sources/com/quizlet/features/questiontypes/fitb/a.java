package com.quizlet.features.questiontypes.fitb;

import androidx.compose.animation.core.J0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends J0 {
    public final String c;
    public final com.quizlet.features.questiontypes.data.a d;
    public final com.quizlet.features.questiontypes.fitb.ui.b e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(String correctAnswer, com.quizlet.features.questiontypes.data.a labelState) {
        super(8);
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(labelState, "labelState");
        this.c = correctAnswer;
        this.d = labelState;
        this.e = new com.quizlet.features.questiontypes.fitb.ui.b(correctAnswer);
    }

    @Override // androidx.compose.animation.core.J0
    public final com.quizlet.features.questiontypes.fitb.ui.e B() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + (this.c.hashCode() * 31);
    }

    @Override // androidx.compose.animation.core.J0
    public final String toString() {
        return "Correct(correctAnswer=" + this.c + ", labelState=" + this.d + ")";
    }

    @Override // androidx.compose.animation.core.J0
    public final com.quizlet.features.questiontypes.data.a x() {
        return this.d;
    }
}
