package com.quizlet.progress.converters;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final long b;
    public final long c;

    public a(long j, long j2, long j3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AnswerSummaryKey(containerId=");
        sb.append(this.a);
        sb.append(", itemId=");
        sb.append(this.b);
        sb.append(", date=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
