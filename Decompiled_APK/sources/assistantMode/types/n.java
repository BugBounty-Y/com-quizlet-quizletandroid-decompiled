package assistantMode.types;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n extends AbstractC1458e {
    public final List a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.m c;

    public n(List cards, assistantMode.enums.m promptSide, assistantMode.enums.m answerSide) {
        Intrinsics.checkNotNullParameter(cards, "cards");
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        this.a = cards;
        this.b = promptSide;
        this.c = answerSide;
    }

    @Override // assistantMode.types.AbstractC1458e
    public final List a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b && this.c == nVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + assistantMode.refactored.a.e(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "MultiCardQuestionConfig(cards=" + this.a + ", promptSide=" + this.b + ", answerSide=" + this.c + ")";
    }
}
