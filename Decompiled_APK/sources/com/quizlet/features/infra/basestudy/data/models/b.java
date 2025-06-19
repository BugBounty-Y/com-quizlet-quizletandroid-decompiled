package com.quizlet.features.infra.basestudy.data.models;

/* loaded from: classes3.dex */
public final class b implements w {
    public final long a;

    public b(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a == ((b) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("CopySet(setId="));
    }
}
