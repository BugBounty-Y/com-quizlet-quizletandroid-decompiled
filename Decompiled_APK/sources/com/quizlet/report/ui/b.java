package com.quizlet.report.ui;

import com.quizlet.generated.enums.Q0;

/* loaded from: classes3.dex */
public final class b {
    public final Q0 a;

    public b(Q0 q0) {
        this.a = q0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a == ((b) obj).a;
    }

    public final int hashCode() {
        Q0 q0 = this.a;
        if (q0 == null) {
            return 0;
        }
        return q0.hashCode();
    }

    public final String toString() {
        return "ReportResult(reportReason=" + this.a + ")";
    }
}
