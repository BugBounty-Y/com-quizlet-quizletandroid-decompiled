package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class E1 implements D1 {
    public final long a;
    public final long b;
    public final long c;
    public final int d;

    public E1(long j, long j2, int i, long j3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = i;
    }

    @Override // com.quizlet.data.model.D1
    public final long a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E1)) {
            return false;
        }
        E1 e1 = (E1) obj;
        return this.a == e1.a && this.b == e1.b && this.c == e1.c && this.d == e1.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    @Override // com.quizlet.data.model.D1
    public final long i() {
        return this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectedTerm(termId=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", setId=");
        sb.append(this.c);
        sb.append(", source=");
        return android.support.v4.media.session.a.r(sb, this.d, ")");
    }
}
