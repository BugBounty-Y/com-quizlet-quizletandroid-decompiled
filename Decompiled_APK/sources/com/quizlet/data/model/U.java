package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class U {
    public final ExerciseDetails a;
    public final X b;
    public final boolean c;

    public U(ExerciseDetails exerciseDetails, X x, boolean z) {
        Intrinsics.checkNotNullParameter(exerciseDetails, "exerciseDetails");
        this.a = exerciseDetails;
        this.b = x;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U)) {
            return false;
        }
        U u = (U) obj;
        return Intrinsics.b(this.a, u.a) && Intrinsics.b(this.b, u.b) && this.c == u.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        X x = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (x == null ? 0 : x.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseDetailsWithMetering(exerciseDetails=");
        sb.append(this.a);
        sb.append(", meteringInfo=");
        sb.append(this.b);
        sb.append(", isContentLimited=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
