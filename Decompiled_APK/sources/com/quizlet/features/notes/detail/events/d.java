package com.quizlet.features.notes.detail.events;

/* loaded from: classes3.dex */
public final class d implements p {
    public final long a;

    public d(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && this.a == ((d) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("EditSet(setId="));
    }
}
