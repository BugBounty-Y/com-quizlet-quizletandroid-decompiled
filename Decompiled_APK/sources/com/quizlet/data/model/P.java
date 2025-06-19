package com.quizlet.data.model;

/* loaded from: classes2.dex */
public final class P extends AbstractC4119d0 {
    public final long a;
    public final boolean b;
    public final long c;
    public final long d;
    public final boolean e;

    public P(boolean z, long j, long j2, boolean z2, long j3) {
        this.a = j;
        this.b = z;
        this.c = j2;
        this.d = j3;
        this.e = z2;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public final long a() {
        return this.a;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public final long b() {
        return this.c;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public final long c() {
        return this.d;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public final boolean d() {
        return this.b;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public final boolean e() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof P)) {
            return false;
        }
        P p = (P) obj;
        return this.a == p.a && this.b == p.b && this.c == p.c && this.d == p.d && this.e == p.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DeletedFolder(id=");
        sb.append(this.a);
        sb.append(", isDeleted=");
        sb.append(this.b);
        sb.append(", lastModified=");
        sb.append(this.c);
        sb.append(", localId=");
        sb.append(this.d);
        sb.append(", isDirty=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
