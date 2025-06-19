package com.quizlet.features.notes.data;

/* loaded from: classes3.dex */
public final class r implements x {
    public final int a;

    public r(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && this.a == ((r) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("NotEnoughCharacters(minimumCharacters="), this.a, ")");
    }
}
