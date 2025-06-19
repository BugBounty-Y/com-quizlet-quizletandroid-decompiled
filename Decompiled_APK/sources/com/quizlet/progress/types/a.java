package com.quizlet.progress.types;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.progress.enums.a a;
    public final long b;
    public final com.quizlet.progress.enums.b c;

    public a(com.quizlet.progress.enums.a correctness, long j, com.quizlet.progress.enums.b studyModeType) {
        Intrinsics.checkNotNullParameter(correctness, "correctness");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        this.a = correctness;
        this.b = j;
        this.c = studyModeType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.d(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "AnswerHistory(correctness=" + this.a + ", timestamp=" + this.b + ", studyModeType=" + this.c + ")";
    }
}
