package assistantMode.stepGenerators.types;

import assistantMode.grading.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final b a;
    public final d b;

    public c(b step, d dVar) {
        Intrinsics.checkNotNullParameter(step, "step");
        this.a = step;
        this.b = dVar;
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
        int iHashCode = this.a.hashCode() * 31;
        d dVar = this.b;
        return iHashCode + (dVar == null ? 0 : dVar.hashCode());
    }

    public final String toString() {
        return "TaskStepData(step=" + this.a + ", grader=" + this.b + ")";
    }
}
