package com.quizlet.features.match.data;

/* loaded from: classes3.dex */
public final class r extends AbstractC4363t {
    public final long a;
    public final long b;

    public r(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && this.b == rVar.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Resumed(timeStarted=");
        sb.append(this.a);
        sb.append(", penalty=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
