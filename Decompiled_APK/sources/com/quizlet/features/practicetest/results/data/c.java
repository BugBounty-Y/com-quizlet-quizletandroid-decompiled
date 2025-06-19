package com.quizlet.features.practicetest.results.data;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4501m0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final String a;
    public final String b;
    public final EnumC4501m0 c;

    public c(String userAnswer, String correctAnswer, EnumC4501m0 grade) {
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(grade, "grade");
        this.a = userAnswer;
        this.b = correctAnswer;
        this.c = grade;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "WrittenAnswer(userAnswer=" + this.a + ", correctAnswer=" + this.b + ", grade=" + this.c + ")";
    }
}
