package com.quizlet.features.match.logging;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final MixedOptionMatchingStudiableQuestion a;
    public final int b;
    public final Integer c;

    public c(MixedOptionMatchingStudiableQuestion question, int i, Integer num) {
        Intrinsics.checkNotNullParameter(question, "question");
        this.a = question;
        this.b = i;
        this.c = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && this.b == cVar.b && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, this.a.hashCode() * 31, 31);
        Integer num = this.c;
        return iB + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MatchQuestionActionLogData(question=");
        sb.append(this.a);
        sb.append(", firstIndex=");
        sb.append(this.b);
        sb.append(", secondIndex=");
        return assistantMode.refactored.a.l(sb, this.c, ")");
    }
}
