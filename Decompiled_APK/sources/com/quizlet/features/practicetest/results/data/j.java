package com.quizlet.features.practicetest.results.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements n {
    public final int a;
    public final String b;

    public j(int i, String questionId) {
        Intrinsics.checkNotNullParameter(questionId, "questionId");
        this.a = i;
        this.b = questionId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "ReportQuestionIconClicked(modelType=" + this.a + ", questionId=" + this.b + ")";
    }
}
