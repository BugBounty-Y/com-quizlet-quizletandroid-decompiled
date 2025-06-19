package com.quizlet.search.navigation;

/* loaded from: classes3.dex */
public final class g extends l {
    public final long a;

    public g(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && this.a == ((g) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("StudySet(studySetId="));
    }
}
