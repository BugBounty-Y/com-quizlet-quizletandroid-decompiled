package com.quizlet.features.setpage.header.data;

/* loaded from: classes3.dex */
public final class c {
    public final long a;

    public c(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a == ((c) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("GoToProfile(id="));
    }
}
