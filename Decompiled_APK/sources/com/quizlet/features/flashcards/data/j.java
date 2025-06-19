package com.quizlet.features.flashcards.data;

import com.quizlet.generated.enums.A1;

/* loaded from: classes2.dex */
public final class j extends l {
    public final long a;
    public final A1 b;

    public j(long j, A1 a1) {
        this.a = j;
        this.b = a1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && this.b == jVar.b;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        A1 a1 = this.b;
        return iHashCode + (a1 == null ? 0 : a1.hashCode());
    }

    public final String toString() {
        return "SignupWall(setId=" + this.a + ", studyModeRedirect=" + this.b + ")";
    }
}
