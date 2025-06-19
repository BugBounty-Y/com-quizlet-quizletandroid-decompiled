package com.quizlet.features.match.data;

/* renamed from: com.quizlet.features.match.data.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4362s extends AbstractC4363t {
    public final long a;

    public C4362s(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4362s) && this.a == ((C4362s) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("Started(timeStarted="));
    }
}
