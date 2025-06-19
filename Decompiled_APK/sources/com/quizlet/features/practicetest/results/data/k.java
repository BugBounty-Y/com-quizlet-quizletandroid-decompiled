package com.quizlet.features.practicetest.results.data;

import com.quizlet.generated.enums.Q0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements n {
    public final Q0 a;

    public k(Q0 reportReason) {
        Intrinsics.checkNotNullParameter(reportReason, "reportReason");
        this.a = reportReason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && this.a == ((k) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ReportQuestionSubmitted(reportReason=" + this.a + ")";
    }
}
