package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: assistantMode.types.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1459f {
    public final long a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.m c;
    public final assistantMode.enums.k d;

    public C1459f(long j, assistantMode.enums.m promptSide, assistantMode.enums.m answerSide, assistantMode.enums.k questionType) {
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = j;
        this.b = promptSide;
        this.c = answerSide;
        this.d = questionType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1459f)) {
            return false;
        }
        C1459f c1459f = (C1459f) obj;
        return this.a == c1459f.a && this.b == c1459f.b && this.c == c1459f.c && this.d == c1459f.d;
    }

    public final int hashCode() {
        return (this.d.hashCode() + assistantMode.refactored.a.e(this.c, assistantMode.refactored.a.e(this.b, Long.hashCode(this.a) * 31, 31), 31)) * 31;
    }

    public final String toString() {
        return "CardQuestionSpec(cardId=" + this.a + ", promptSide=" + this.b + ", answerSide=" + this.c + ", questionType=" + this.d + ", questionScoringInferenceMetadata=null)";
    }
}
