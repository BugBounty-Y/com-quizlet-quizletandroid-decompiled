package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: assistantMode.types.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1457d {
    public final C1454a a;
    public final assistantMode.enums.m b;
    public final assistantMode.enums.m c;

    public C1457d(C1454a card, assistantMode.enums.m promptSide, assistantMode.enums.m answerSide) {
        Intrinsics.checkNotNullParameter(card, "card");
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        this.a = card;
        this.b = promptSide;
        this.c = answerSide;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1457d)) {
            return false;
        }
        C1457d c1457d = (C1457d) obj;
        return Intrinsics.b(this.a, c1457d.a) && this.b == c1457d.b && this.c == c1457d.c;
    }

    public final int hashCode() {
        return assistantMode.refactored.a.e(this.c, assistantMode.refactored.a.e(this.b, this.a.hashCode() * 31, 31), 31);
    }

    public final String toString() {
        return "CardEdge(card=" + this.a + ", promptSide=" + this.b + ", answerSide=" + this.c + ", questionScoringInferenceMetadata=null)";
    }
}
