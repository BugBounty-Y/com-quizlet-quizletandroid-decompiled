package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class F1 {
    public final long a;
    public final long b;

    public F1(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F1)) {
            return false;
        }
        F1 f1 = (F1) obj;
        return this.a == f1.a && this.b == f1.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectedTermId(termId=");
        sb.append(this.a);
        sb.append(", userId=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }
}
