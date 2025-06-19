package com.quizlet.data.model;

/* renamed from: com.quizlet.data.model.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4181y {
    public final long a;
    public final long b;
    public final long c;
    public final boolean d;
    public final long e;

    public C4181y(long j, long j2, long j3, boolean z, long j4) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = z;
        this.e = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4181y)) {
            return false;
        }
        C4181y c4181y = (C4181y) obj;
        return this.a == c4181y.a && this.b == c4181y.b && this.c == c4181y.c && this.d == c4181y.d && this.e == c4181y.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Bookmark(localId=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", isDeleted=");
        sb.append(this.d);
        sb.append(", lastModified=");
        return android.support.v4.media.session.a.g(this.e, ")", sb);
    }
}
