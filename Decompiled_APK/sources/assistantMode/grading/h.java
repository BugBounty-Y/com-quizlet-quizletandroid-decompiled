package assistantMode.grading;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final boolean a;
    public final grading.core.e b;
    public final b c;

    public h(boolean z, grading.core.e eVar, b gradedAnswerMetadata) {
        Intrinsics.checkNotNullParameter(gradedAnswerMetadata, "gradedAnswerMetadata");
        this.a = z;
        this.b = eVar;
        this.c = gradedAnswerMetadata;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        grading.core.e eVar = this.b;
        return this.c.hashCode() + ((iHashCode + (eVar == null ? 0 : eVar.hashCode())) * 31);
    }

    public final String toString() {
        return "SmarterGraderResult(isCorrect=" + this.a + ", suggestion=" + this.b + ", gradedAnswerMetadata=" + this.c + ")";
    }
}
