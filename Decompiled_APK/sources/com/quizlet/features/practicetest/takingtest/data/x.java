package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x implements y {
    public final C4414h a;

    public x(C4414h answer) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        this.a = answer;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof x) && Intrinsics.b(this.a, ((x) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "WrittenAnswerChanged(answer=" + this.a + ")";
    }
}
