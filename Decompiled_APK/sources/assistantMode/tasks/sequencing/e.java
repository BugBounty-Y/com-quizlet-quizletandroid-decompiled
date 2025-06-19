package assistantMode.tasks.sequencing;

import assistantMode.enums.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final assistantMode.refactored.types.d a;
    public final assistantMode.grading.d b;
    public final k c;

    public e(assistantMode.refactored.types.d question, assistantMode.grading.d grader, k desiredQuestionType) {
        Intrinsics.checkNotNullParameter(question, "question");
        Intrinsics.checkNotNullParameter(grader, "grader");
        Intrinsics.checkNotNullParameter(desiredQuestionType, "desiredQuestionType");
        this.a = question;
        this.b = grader;
        this.c = desiredQuestionType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && this.c == eVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "RoundStep(question=" + this.a + ", grader=" + this.b + ", desiredQuestionType=" + this.c + ")";
    }
}
