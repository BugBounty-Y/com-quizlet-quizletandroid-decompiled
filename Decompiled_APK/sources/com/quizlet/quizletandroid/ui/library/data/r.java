package com.quizlet.quizletandroid.ui.library.data;

/* loaded from: classes3.dex */
public final class r extends F {
    public final long a;

    public r(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && this.a == ((r) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("EditSet(studySetId="));
    }
}
