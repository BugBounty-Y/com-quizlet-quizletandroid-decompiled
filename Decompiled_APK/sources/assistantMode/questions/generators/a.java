package assistantMode.questions.generators;

import assistantMode.enums.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final m a;
    public final m b;

    public a(m promptSide, m answerSide) {
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        this.a = promptSide;
        this.b = answerSide;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "CardSideLabelMetadata(promptSide=" + this.a + ", answerSide=" + this.b + ")";
    }
}
