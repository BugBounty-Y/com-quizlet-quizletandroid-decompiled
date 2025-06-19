package com.quizlet.features.onboarding.ell;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v extends x {
    public final kotlinx.collections.immutable.b a;

    public v(kotlinx.collections.immutable.b selectedExams) {
        Intrinsics.checkNotNullParameter(selectedExams, "selectedExams");
        this.a = selectedExams;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof v) && Intrinsics.b(this.a, ((v) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "EnglishExamsSelection(selectedExams=" + this.a + ")";
    }
}
