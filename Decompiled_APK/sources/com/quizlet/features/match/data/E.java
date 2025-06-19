package com.quizlet.features.match.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E extends G {
    public final List a;
    public final int b;

    public E(List highScores, int i) {
        Intrinsics.checkNotNullParameter(highScores, "highScores");
        this.a = highScores;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return Intrinsics.b(this.a, e.a) && this.b == e.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Scores(highScores=" + this.a + ", usersPosition=" + this.b + ")";
    }
}
