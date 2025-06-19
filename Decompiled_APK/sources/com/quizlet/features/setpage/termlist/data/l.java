package com.quizlet.features.setpage.termlist.data;

/* loaded from: classes3.dex */
public final class l {
    public final long a;

    public l(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && this.a == ((l) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("GoToDiagramOverview(setId="));
    }
}
