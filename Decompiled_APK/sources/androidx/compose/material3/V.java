package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class V {
    public final long a;
    public final long b;
    public final long c;
    public final long d;

    public V(long j, long j2, long j3, long j4) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof V)) {
            return false;
        }
        V v = (V) obj;
        return C0861v.c(this.a, v.a) && C0861v.c(this.b, v.b) && C0861v.c(this.c, v.c) && C0861v.c(this.d, v.d);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }
}
