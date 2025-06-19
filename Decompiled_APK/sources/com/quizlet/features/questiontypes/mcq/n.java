package com.quizlet.features.questiontypes.mcq;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends o {
    public final com.quizlet.features.questiontypes.mcq.data.d a;

    public n(com.quizlet.features.questiontypes.mcq.data.d questionState) {
        Intrinsics.checkNotNullParameter(questionState, "questionState");
        this.a = questionState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ViewState(questionState=" + this.a + ")";
    }
}
