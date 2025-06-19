package assistantMode.types;

import assistantMode.refactored.modelTypes.CustomMultipleChoiceQuestion;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: assistantMode.types.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1460g extends p {
    public final CustomMultipleChoiceQuestion a;

    public C1460g(CustomMultipleChoiceQuestion customMultipleChoiceQuestion) {
        Intrinsics.checkNotNullParameter(customMultipleChoiceQuestion, "customMultipleChoiceQuestion");
        this.a = customMultipleChoiceQuestion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C1460g) && Intrinsics.b(this.a, ((C1460g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CustomMultipleChoiceQuestionConfig(customMultipleChoiceQuestion=" + this.a + ")";
    }
}
