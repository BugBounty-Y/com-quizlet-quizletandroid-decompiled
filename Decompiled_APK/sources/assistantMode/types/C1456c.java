package assistantMode.types;

import androidx.compose.animation.d0;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: assistantMode.types.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1456c {
    public final Boolean a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.k c;
    public final long d;
    public final long e;
    public final Boolean f;
    public final LinkedHashMap g;

    public C1456c(Boolean bool, assistantMode.enums.m answerSide, assistantMode.enums.k questionType, long j, long j2, Boolean bool2, LinkedHashMap delaySecondsByAnswerSide) {
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        Intrinsics.checkNotNullParameter(delaySecondsByAnswerSide, "delaySecondsByAnswerSide");
        this.a = bool;
        this.b = answerSide;
        this.c = questionType;
        this.d = j;
        this.e = j2;
        this.f = bool2;
        this.g = delaySecondsByAnswerSide;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1456c)) {
            return false;
        }
        C1456c c1456c = (C1456c) obj;
        return Intrinsics.b(this.a, c1456c.a) && this.b == c1456c.b && this.c == c1456c.c && this.d == c1456c.d && this.e == c1456c.e && Intrinsics.b(this.f, c1456c.f) && this.g.equals(c1456c.g);
    }

    public final int hashCode() {
        Boolean bool = this.a;
        int iD = d0.d(d0.d((this.c.hashCode() + assistantMode.refactored.a.e(this.b, (bool == null ? 0 : bool.hashCode()) * 31, 31)) * 31, 31, this.d), 31, this.e);
        Boolean bool2 = this.f;
        return this.g.hashCode() + d0.g(d0.g((iD + (bool2 == null ? 0 : bool2.hashCode())) * 31, 31, false), 31, false);
    }

    public final String toString() {
        return "AnswerFeatures(isCorrect=" + this.a + ", answerSide=" + this.b + ", questionType=" + this.c + ", studiableItemId=" + this.d + ", timestamp=" + this.e + ", showedHint=" + this.f + ", userAnswerLangMatch=false, userPromptLangMatch=false, delaySecondsByAnswerSide=" + this.g + ")";
    }
}
