package com.quizlet.features.questiontypes.truefalse;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final com.quizlet.features.questiontypes.composables.a a;
    public final com.quizlet.features.questiontypes.composables.a b;
    public final com.quizlet.features.questiontypes.data.a c;

    public d(com.quizlet.features.questiontypes.composables.a trueButtonStatus, com.quizlet.features.questiontypes.composables.a falseButtonStatus, com.quizlet.features.questiontypes.data.a labelState) {
        Intrinsics.checkNotNullParameter(trueButtonStatus, "trueButtonStatus");
        Intrinsics.checkNotNullParameter(falseButtonStatus, "falseButtonStatus");
        Intrinsics.checkNotNullParameter(labelState, "labelState");
        this.a = trueButtonStatus;
        this.b = falseButtonStatus;
        this.c = labelState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && Intrinsics.b(this.c, dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "TrueFalseAnswerState(trueButtonStatus=" + this.a + ", falseButtonStatus=" + this.b + ", labelState=" + this.c + ")";
    }
}
