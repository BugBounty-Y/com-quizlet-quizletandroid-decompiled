package com.quizlet.shared.cache;

/* loaded from: classes3.dex */
public final class j {
    public final long a;

    public j(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && this.a == ((j) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("InMemoryCacheConfiguration(maxSizeBytes="));
    }
}
