package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4420n implements y {
    public final C4413g a;

    public C4420n(C4413g answer) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = answer;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4420n) && Intrinsics.b(this.a, ((C4420n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MultipleChoiceOptionClicked(answer=" + this.a + ")";
    }
}
