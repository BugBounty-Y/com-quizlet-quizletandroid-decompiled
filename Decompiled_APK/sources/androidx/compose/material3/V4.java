package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class V4 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;

    public V4(long j, long j2, long j3, long j4, long j5) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
    }

    public final V4 a(long j, long j2, long j3, long j4, long j5) {
        return new V4(j != 16 ? j : this.a, j2 != 16 ? j2 : this.b, j3 != 16 ? j3 : this.c, j4 != 16 ? j4 : this.d, j5 != 16 ? j5 : this.e);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof V4)) {
            return false;
        }
        V4 v4 = (V4) obj;
        return C0861v.c(this.a, v4.a) && C0861v.c(this.b, v4.b) && C0861v.c(this.c, v4.c) && C0861v.c(this.d, v4.d) && C0861v.c(this.e, v4.e);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.e) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
    }
}
