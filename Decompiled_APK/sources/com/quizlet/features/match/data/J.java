package com.quizlet.features.match.data;

/* loaded from: classes3.dex */
public final class J extends M {
    public final int a;

    public J(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof J) && this.a == ((J) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("HasSelected(starCount="), this.a, ")");
    }
}
