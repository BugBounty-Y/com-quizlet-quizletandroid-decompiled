package assistantMode.types;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class q {
    public final long a;
    public final assistantMode.enums.k b;

    public q(long j, assistantMode.enums.k questionType) {
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = j;
        this.b = questionType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return this.a == qVar.a && this.b == qVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "QuestionTypeStudiableItemTuple(studiableItemId=" + this.a + ", questionType=" + this.b + ")";
    }
}
