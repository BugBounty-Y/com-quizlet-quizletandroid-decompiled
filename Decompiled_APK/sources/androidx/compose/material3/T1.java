package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class T1 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;

    public T1(long j, long j2, long j3, long j4, long j5, long j6) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof T1)) {
            return false;
        }
        T1 t1 = (T1) obj;
        return C0861v.c(this.a, t1.a) && C0861v.c(this.b, t1.b) && C0861v.c(this.c, t1.c) && C0861v.c(this.d, t1.d) && C0861v.c(this.e, t1.e) && C0861v.c(this.f, t1.f);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.f) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }
}
