package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class K {
    public final long a;
    public final long b;
    public final long c;
    public final long d;

    public K(long j, long j2, long j3, long j4) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
    }

    public final K a(long j, long j2, long j3, long j4) {
        if (j == 16) {
            j = this.a;
        }
        return new K(j, j2 != 16 ? j2 : this.b, j3 != 16 ? j3 : this.c, j4 != 16 ? j4 : this.d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof K)) {
            return false;
        }
        K k = (K) obj;
        return C0861v.c(this.a, k.a) && C0861v.c(this.b, k.b) && C0861v.c(this.c, k.c) && C0861v.c(this.d, k.d);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.d) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }
}
