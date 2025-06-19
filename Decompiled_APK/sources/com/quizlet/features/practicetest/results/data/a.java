package com.quizlet.features.practicetest.results.data;

import com.quizlet.generated.enums.EnumC4501m0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final e a;
    public final e b;
    public final EnumC4501m0 c;
    public final kotlinx.collections.immutable.e d;

    public a(e userAnswer, e correctAnswer, EnumC4501m0 grade, kotlinx.collections.immutable.e unselectedOptions) {
        Intrinsics.checkNotNullParameter(userAnswer, "userAnswer");
        Intrinsics.checkNotNullParameter(correctAnswer, "correctAnswer");
        Intrinsics.checkNotNullParameter(grade, "grade");
        Intrinsics.checkNotNullParameter(unselectedOptions, "unselectedOptions");
        this.a = userAnswer;
        this.b = correctAnswer;
        this.c = grade;
        this.d = unselectedOptions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && this.b.equals(aVar.b) && this.c == aVar.c && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "MultipleChoiceAnswer(userAnswer=" + this.a + ", correctAnswer=" + this.b + ", grade=" + this.c + ", unselectedOptions=" + this.d + ")";
    }
}
