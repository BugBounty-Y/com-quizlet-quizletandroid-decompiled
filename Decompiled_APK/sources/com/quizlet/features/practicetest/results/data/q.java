package com.quizlet.features.practicetest.results.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements s {
    public final int a;
    public final String b;

    public q(int i, String questionId) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        this.a = i;
        this.b = questionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && Intrinsics.b(this.b, qVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ReportQuestion(modelType=" + this.a + ", questionId=" + this.b + ")";
    }
}
