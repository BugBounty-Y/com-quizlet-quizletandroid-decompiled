package assistantMode.questions.generators;

import assistantMode.types.QuestionElement;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final QuestionElement a;
    public final assistantMode.enums.i b;

    public c(QuestionElement option, assistantMode.enums.i optionSource) {
        Intrinsics.checkNotNullParameter(option, "option");
        Intrinsics.checkNotNullParameter(optionSource, "optionSource");
        this.a = option;
        this.b = optionSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.a.hashCode() * 31);
    }

    public final String toString() {
        return "PairOptionAndSource(option=" + this.a + ", optionSource=" + this.b + ")";
    }
}
