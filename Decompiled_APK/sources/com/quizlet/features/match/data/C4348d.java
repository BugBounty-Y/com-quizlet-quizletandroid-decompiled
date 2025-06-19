package com.quizlet.features.match.data;

/* renamed from: com.quizlet.features.match.data.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4348d extends AbstractC4368y {
    public final long a;
    public final long b;

    public C4348d(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4348d)) {
            return false;
        }
        C4348d c4348d = (C4348d) obj;
        return this.a == c4348d.a && this.b == c4348d.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EndGame(endTime=");
        sb.append(this.a);
        sb.append(", finalPenalty=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
