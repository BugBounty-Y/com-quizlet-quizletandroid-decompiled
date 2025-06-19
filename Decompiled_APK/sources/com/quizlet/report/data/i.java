package com.quizlet.report.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final com.quizlet.report.ui.b a;

    public i(com.quizlet.report.ui.b reportResult) {
        Intrinsics.checkNotNullParameter(reportResult, "reportResult");
        this.a = reportResult;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Close(reportResult=" + this.a + ")";
    }
}
