package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j2 {
    public final i2 a;
    public final StudySet b;

    public j2(i2 term, StudySet studySet) {
        Intrinsics.checkNotNullParameter(term, "term");
        this.a = term;
        this.b = studySet;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j2)) {
            return false;
        }
        j2 j2Var = (j2) obj;
        return Intrinsics.b(this.a, j2Var.a) && Intrinsics.b(this.b, j2Var.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        StudySet studySet = this.b;
        return iHashCode + (studySet == null ? 0 : studySet.hashCode());
    }

    public final String toString() {
        return "TermWithSet(term=" + this.a + ", studySet=" + this.b + ")";
    }
}
