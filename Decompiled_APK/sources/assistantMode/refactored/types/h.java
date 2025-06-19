package assistantMode.refactored.types;

import assistantMode.enums.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final Task a;
    public final k b;

    public h(Task task, k questionType) {
        Intrinsics.checkNotNullParameter(task, "task");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = task;
        this.b = questionType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.a.hashCode() * 31);
    }

    public final String toString() {
        return "TaskQuestionTypePair(task=" + this.a + ", questionType=" + this.b + ")";
    }
}
