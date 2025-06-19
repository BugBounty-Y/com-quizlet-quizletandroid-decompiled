package com.quizlet.features.match.data;

/* renamed from: com.quizlet.features.match.data.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4361q extends AbstractC4363t {
    public final long a;

    public C4361q(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4361q) && this.a == ((C4361q) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.g(this.a, ")", new StringBuilder("Penalty(penalty="));
    }
}
