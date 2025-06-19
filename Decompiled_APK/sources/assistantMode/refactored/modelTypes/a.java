package assistantMode.refactored.modelTypes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final CardSideDistractor a;

    public a(CardSideDistractor distractor) {
        Intrinsics.checkNotNullParameter(distractor, "distractor");
        this.a = distractor;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.a.hashCode();
    }

    public final String toString() {
        return "AnnotatedCardSideDistractorShim(distractor=" + this.a + ")";
    }
}
