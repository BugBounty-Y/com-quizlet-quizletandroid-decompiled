package com.quizlet.diagrams;

/* loaded from: classes2.dex */
public final class f {
    public final long a;
    public final boolean b;

    public f(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && this.b == fVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "TermClickEvent(termId=" + this.a + ", isSelected=" + this.b + ")";
    }
}
