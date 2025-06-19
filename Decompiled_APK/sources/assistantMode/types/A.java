package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A {
    public final assistantMode.enums.m a;
    public final assistantMode.enums.m b;

    public A(assistantMode.enums.m promptSide, assistantMode.enums.m answerSide) {
        Intrinsics.checkNotNullParameter(promptSide, "promptSide");
        Intrinsics.checkNotNullParameter(answerSide, "answerSide");
        this.a = promptSide;
        this.b = answerSide;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A)) {
            return false;
        }
        A a = (A) obj;
        return this.a == a.a && this.b == a.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "SidePair(promptSide=" + this.a + ", answerSide=" + this.b + ")";
    }
}
