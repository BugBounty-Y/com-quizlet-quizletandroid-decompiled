package com.quizlet.studiablemodels.grading;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final StudiableQuestionGradedAnswer a;
    public final boolean b;
    public final PGradedAnswerMetadata c;

    public b(StudiableQuestionGradedAnswer gradedAnswer, boolean z, PGradedAnswerMetadata gradedAnswerMetadata) {
        Intrinsics.checkNotNullParameter(gradedAnswer, "gradedAnswer");
        Intrinsics.checkNotNullParameter(gradedAnswerMetadata, "gradedAnswerMetadata");
        this.a = gradedAnswer;
        this.b = z;
        this.c = gradedAnswerMetadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && this.b == bVar.b && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "SmartGradingResult(gradedAnswer=" + this.a + ", didUseSmartGrading=" + this.b + ", gradedAnswerMetadata=" + this.c + ")";
    }
}
