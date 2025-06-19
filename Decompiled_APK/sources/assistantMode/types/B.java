package assistantMode.types;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class B extends AbstractC1458e {
    public final C1457d a;

    public B(C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        this.a = cardEdge;
    }

    @Override // assistantMode.types.AbstractC1458e
    public final List a() {
        return kotlin.collections.A.b(this.a.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B) && Intrinsics.b(this.a, ((B) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SingleCardQuestionConfig(cardEdge=" + this.a + ")";
    }
}
