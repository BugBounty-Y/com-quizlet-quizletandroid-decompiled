package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class p2 implements D1 {
    public final long a;
    public final long b;
    public final boolean c;

    public p2(long j, long j2, boolean z) {
        this.a = j;
        this.b = j2;
        this.c = z;
    }

    @Override // com.quizlet.data.model.D1
    public final long a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p2)) {
            return false;
        }
        p2 p2Var = (p2) obj;
        return this.a == p2Var.a && this.b == p2Var.b && this.c == p2Var.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    @Override // com.quizlet.data.model.D1
    public final long i() {
        return this.b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UnselectedTerm(termId=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
