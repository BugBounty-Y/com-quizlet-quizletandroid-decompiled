package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class D2 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;

    public D2(long j, long j2, long j3, long j4, long j5, long j6, long j7) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
        this.g = j7;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof D2)) {
            return false;
        }
        D2 d2 = (D2) obj;
        return C0861v.c(this.a, d2.a) && C0861v.c(this.d, d2.d) && C0861v.c(this.b, d2.b) && C0861v.c(this.e, d2.e) && C0861v.c(this.c, d2.c) && C0861v.c(this.f, d2.f) && C0861v.c(this.g, d2.g);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.g) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.d), 31, this.b), 31, this.e), 31, this.c), 31, this.f);
    }
}
