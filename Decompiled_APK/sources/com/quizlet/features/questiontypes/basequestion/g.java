package com.quizlet.features.questiontypes.basequestion;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends h {
    public final com.quizlet.features.questiontypes.basequestion.data.b a;

    public g(com.quizlet.features.questiontypes.basequestion.data.b state) {
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = state;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FinishQuestion(state=" + this.a + ")";
    }
}
