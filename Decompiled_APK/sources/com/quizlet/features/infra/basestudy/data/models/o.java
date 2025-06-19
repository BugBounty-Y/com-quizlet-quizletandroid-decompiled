package com.quizlet.features.infra.basestudy.data.models;

import com.quizlet.generated.enums.A1;

/* loaded from: classes3.dex */
public final class o implements k, l, j {
    public final long a;
    public final A1 b;

    public o(long j, A1 a1) {
        this.a = j;
        this.b = a1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        A1 a1 = this.b;
        return iHashCode + (a1 == null ? 0 : a1.hashCode());
    }

    public final String toString() {
        return "SignUpWall(setId=" + this.a + ", studyModeRedirect=" + this.b + ")";
    }
}
