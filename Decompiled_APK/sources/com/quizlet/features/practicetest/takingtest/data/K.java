package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class K {
    public final String a;
    public final F b;

    public K(String practiceTestId, F content) {
        Intrinsics.checkNotNullParameter(practiceTestId, "practiceTestId");
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = practiceTestId;
        this.b = content;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof K)) {
            return false;
        }
        K k = (K) obj;
        return Intrinsics.b(this.a, k.a) && Intrinsics.b(this.b, k.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "QuestionContentWithPracticeTestId(practiceTestId=" + this.a + ", content=" + this.b + ")";
    }
}
