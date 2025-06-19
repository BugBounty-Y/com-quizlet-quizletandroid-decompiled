package com.quizlet.features.questionnaire.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends i {
    public final StepModel a;

    public f(StepModel step) {
        Intrinsics.checkNotNullParameter(step, "step");
        this.a = step;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CurrentStep(step=" + this.a + ")";
    }
}
