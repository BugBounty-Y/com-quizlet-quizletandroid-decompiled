package com.quizlet.features.match.data;

/* loaded from: classes3.dex */
public final class L extends M {
    public final int a;

    public L(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof L) && this.a == ((L) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("StudySelected(starCount="), this.a, ")");
    }
}
