package com.quizlet.features.practicetest.takingtest.data;

import com.quizlet.generated.enums.Q0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class t implements y {
    public final Q0 a;

    public t(Q0 reportReason) {
        Intrinsics.checkNotNullParameter(reportReason, "reportReason");
        this.a = reportReason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && this.a == ((t) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ReportSubmitted(reportReason=" + this.a + ")";
    }
}
