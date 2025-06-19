package com.quizlet.features.match.data;

/* renamed from: com.quizlet.features.match.data.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4364u extends AbstractC4367x {
    public final long a;
    public final long b;

    public C4364u(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4364u)) {
            return false;
        }
        C4364u c4364u = (C4364u) obj;
        return this.a == c4364u.a && this.b == c4364u.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Finished(endTime=");
        sb.append(this.a);
        sb.append(", finalPenalty=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
